using Den.Dev.Orion.Authentication;
using Den.Dev.Orion.Core;
using Den.Dev.Orion.Models;
using Den.Dev.Orion.Models.HaloInfinite;
using Den.Dev.Orion.Models.Security;
using Microsoft.Data.Sqlite;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Extensions.Msal;
using OpenSpartan.FilmEventExtractor.Models;
using OpenSpartan.FilmEventExtractor.Terminal;
using System.Collections.Concurrent;
using System.IO.Compression;
using System.Net;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;

namespace OpenSpartan.FilmEventExtractor
{
    internal class Program
    {
        internal static readonly string CacheFileName = "credcache.bin";
        internal static readonly string[] Scopes = ["Xboxlive.signin", "Xboxlive.offline_access"];
        internal static readonly string ClientId = "c3ff9fdf-c999-4507-ae2b-b9cab21d6bad";
        internal static readonly string HaloInfiniteAPIRelease = "1.8";
        internal static readonly string ApplicationName = "OpenSpartan.FilmEventExtractor";
        internal static readonly string ApplicationVersion = "0.0.1-09172024";
        internal static readonly string DataConnectionString = @"Data Source=eventlog.db;";
        internal static readonly string LogFileName = "log.txt";
        internal static readonly string ExclusionFileName = "excludedmatchids.json";

        internal static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

        internal static readonly byte[] PlayerIdentificationPattern = { 0x2D, 0xC0 };

        internal static readonly int MatchesPerPage = 25;

        internal static XboxTicket XboxUserContext { get; set; }

        internal static HaloInfiniteClient HaloClient { get; set; }

        static async Task Main(string[] args)
        {
            InitializeLogging();

            Console.WriteLine($"{ApplicationName} ({ApplicationVersion})");
            Console.WriteLine("Authenticating...");
            var authResult = await InitializeApplication();
            if (authResult)
            {
                // Authentication was successful.
                Console.WriteLine("Authentication successful.");

                var matchIds = await GetPlayerMatchIds(XboxUserContext.DisplayClaims.Xui[0].XUID);
                Console.WriteLine($"Obtained {matchIds.Count} match IDs for the current player.");

                // Prepare the database.
                SetWALJournalingMode();

                using SqliteConnection connection = new(DataConnectionString);
                connection.Open();

                if (matchIds != null && matchIds.Count > 0)
                {
                    // We have matches. Let's try and validate what we have against what's already in
                    // the database and the exceptions file.
                    var existingMatches = GetExistingMatchIds(connection);

                    if (existingMatches != null && existingMatches.Count > 0)
                    {
                        Console.WriteLine($"There are {existingMatches.Count} match IDs already registered in the database.");

                        CleanMatchIdList(matchIds, existingMatches);
                    }

                    var excludedMatches = GetExcludedMatches();
                    if (excludedMatches != null && excludedMatches.Count > 0)
                    {
                        Console.WriteLine($"Found {excludedMatches.Count} matches that need to be excluded.");

                        CleanMatchIdList(matchIds, excludedMatches);
                    }

                    foreach (var matchId in matchIds)
                    {
                        Console.WriteLine($"Processing match {matchIds.IndexOf(matchId)} of {matchIds.Count}...");

                        var filmMetadata = await SafeAPICall(async () => await HaloClient.HIUGCDiscoverySpectateByMatchId(matchId.ToString()));
                        if (filmMetadata != null && filmMetadata.Result != null)
                        {
                            // Individual chunks contain player information that we do not have anywhere else - gamertag and XUID combos.
                            // This data is available in all chunks but the final, so we will try and parse it out.
                            var playerTagChunks = filmMetadata.Result.CustomData.Chunks.Where(x => x.ChunkType != 3);

                            // General metadata chunk always has chunk type of 3.
                            var generalMetadataChunk = filmMetadata.Result.CustomData.Chunks.FirstOrDefault(x => x.ChunkType == 3);

                            if (generalMetadataChunk != null)
                            {
                                if (playerTagChunks != null && generalMetadataChunk != null)
                                {
                                    Dictionary<long, string> metaPlayerCollection = [];

                                    bool playerChunksMissing = false;

                                    foreach (var playerTagChunk in playerTagChunks)
                                    {
                                        Console.WriteLine($"Processing {playerTagChunk.FileRelativePath} for {matchId}...");

                                        var url = $"{filmMetadata.Result.BlobStoragePathPrefix}{playerTagChunk.FileRelativePath.Replace("/", string.Empty)}";
                                        Console.WriteLine($"Downloading film chunk from {url}");

                                        try
                                        {
                                            var compressedPlayerData = await DownloadFilm(url);
                                            if (compressedPlayerData != null)
                                            {
                                                var uncompressedPlayerData = UncompressZlib(compressedPlayerData);

                                                var players = ProcessFilmBootstrapData(uncompressedPlayerData, PlayerIdentificationPattern);

                                                foreach (var player in players)
                                                {
                                                    metaPlayerCollection.TryAdd(player.Key, player.Value);
                                                }
                                            }
                                            else
                                            {
                                                Console.WriteLine("Content is null.");
                                            }
                                        }
                                        catch (FileNotFoundException e)
                                        {
                                            // We hit a 404.
                                            ExcludeMatchId(matchId);
                                            playerChunksMissing = true;
                                            break;
                                        }
                                    }

                                    if (!playerChunksMissing)
                                    {
                                        Console.WriteLine("Finished processing individual starter chunks. Identified players:");
                                        foreach (var player in metaPlayerCollection)
                                        {
                                            Console.WriteLine($"{player.Value} ({player.Key})");
                                        }

                                        var compressedMetadata = await DownloadFilm($"{filmMetadata.Result.BlobStoragePathPrefix}{generalMetadataChunk.FileRelativePath.Replace("/", string.Empty)}");

                                        if (compressedMetadata != null)
                                        {
                                            var uncompressedMetadata = UncompressZlib(compressedMetadata);

                                            foreach (var player in metaPlayerCollection)
                                            {
                                                Console.WriteLine($"Searching for events for {player.Value} ({string.Join(" ", Encoding.Unicode.GetBytes(player.Value).Select(b => b.ToString("X2")))})...");
                                                var data = ProcessFilmTimelineData(uncompressedMetadata, Encoding.Unicode.GetBytes(player.Value));

                                                if (data != null && data.Count > 0)
                                                {
                                                    string query = @"INSERT INTO EventLog (EventID, MatchID, Gamertag, XUID, EventType, MedalFlag, EventTime, MetadataValue)
                                                             VALUES (@EventID, @MatchID, @Gamertag, @XUID, @EventType, @MedalFlag, @EventTime, @MetadataValue)";

                                                    foreach (var gameEvent in data)
                                                    {
                                                        // Create a command object
                                                        using SqliteCommand command = new(query, connection);
                                                        // Add parameters to the query
                                                        command.Parameters.AddWithValue("@EventID", Guid.NewGuid().ToString());         // Event ID (Primary Key)
                                                        command.Parameters.AddWithValue("@MatchID", matchId);         // Match ID
                                                        command.Parameters.AddWithValue("@Gamertag", gameEvent.Gamertag);       // Gamertag
                                                        command.Parameters.AddWithValue("@XUID", player.Key);    // XUID
                                                        command.Parameters.AddWithValue("@EventType", gameEvent.TypeHint);           // Event Type
                                                        command.Parameters.AddWithValue("@MedalFlag", gameEvent.IsMedal);                // Medal Flag (Integer)
                                                        command.Parameters.AddWithValue("@EventTime", gameEvent.Timestamp);       // Event Time (Unix timestamp)
                                                        command.Parameters.AddWithValue("@MetadataValue", gameEvent.MedalType);  // Optional Metadata Value

                                                        try
                                                        {
                                                            // Execute the command
                                                            int result = command.ExecuteNonQuery();

                                                            // Output the result
                                                            Console.WriteLine($"{result} row(s) inserted into database.");
                                                        }
                                                        catch (Exception ex)
                                                        {
                                                            Console.WriteLine("Could not insert data into database.");
                                                            Console.WriteLine(ex.ToString());
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        else
                                        {
                                            Console.WriteLine("Content is null.");
                                        }
                                    }
                                    else
                                    {
                                        Console.WriteLine("Interrupting processing. Player chunks are missing, so we can't fully complete the parsing.");
                                        continue;
                                    }
                                }
                                else
                                {
                                    Console.WriteLine($"Could not get film metadata for match {matchId}");
                                }
                            }
                        }
                        else
                        {
                            Console.WriteLine($"Match {matchId} had no metadata chunk of type 3. Cannot process full timeline.");
                            ExcludeMatchId(matchId);
                        }
                    }
                }
            }
            else
            {
                // Authentication was not successful.
                Console.WriteLine("Could not authenticate the user.");
            }
        }

        private static List<string> GetExcludedMatches()
        {
            if (System.IO.File.Exists(ExclusionFileName))
            {
                var jsonContent = System.IO.File.ReadAllText(ExclusionFileName);
                return JsonSerializer.Deserialize<List<string>>(jsonContent) ?? [];
            }
            else
            {
                return [];
            }
        }

        public static void ExcludeMatchId(Guid matchId)
        {
            List<Guid> excludedMatchIds;

            if (System.IO.File.Exists(ExclusionFileName))
            {
                var jsonContent = System.IO.File.ReadAllText(ExclusionFileName);
                excludedMatchIds = JsonSerializer.Deserialize<List<Guid>>(jsonContent) ?? [];
            }
            else
            {
                excludedMatchIds = [];
            }

            if (!excludedMatchIds.Contains(matchId))
            {
                excludedMatchIds.Add(matchId);

                var updatedJson = JsonSerializer.Serialize(excludedMatchIds, options: JsonOptions);
                System.IO.File.WriteAllText(ExclusionFileName, updatedJson);

                Console.WriteLine($"Match ID {matchId} has been added to the banned list.");
            }
            else
            {
                Console.WriteLine($"Match ID {matchId} is already banned.");
            }
        }

        public static void CleanMatchIdList(List<Guid> guidList, List<string> matchIDs)
        {
            List<Guid> matchGuids = [];

            foreach (string matchID in matchIDs)
            {
                if (Guid.TryParse(matchID, out Guid matchGuid))
                {
                    matchGuids.Add(matchGuid);
                }
            }

            guidList.RemoveAll(g => matchGuids.Contains(g));
        }

        public static List<string> GetExistingMatchIds(SqliteConnection connection)
        {
            List<string> matchIDs = [];

            string query = "SELECT DISTINCT MatchID FROM EventLog";

            using (SqliteCommand command = new(query, connection))
            {
                using SqliteDataReader reader = command.ExecuteReader();

                while (reader.Read())
                {
                    matchIDs.Add(reader["MatchID"].ToString());
                }
            }

            return matchIDs;
        }

        static void InitializeLogging()
        {
            StreamWriter logFileWriter = new(LogFileName, append: false)
            {
                AutoFlush = true
            };

            MultiTextWriter multiWriter = new(Console.Out, logFileWriter);

            Console.SetOut(multiWriter);
        }

        internal static string SetWALJournalingMode()
        {
            try
            {
                using var connection = new SqliteConnection(DataConnectionString);
                connection.Open();

                using var command = connection.CreateCommand();
                command.CommandText = "PRAGMA journal_mode=WAL;";

                using var reader = command.ExecuteReader();
                if (reader.Read())
                {
                    return reader.GetString(0).Trim();
                }

                Console.WriteLine($"WAL journaling mode not set.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Journaling mode modification exception: {ex.Message}");
            }

            return null;
        }

        static byte[] UncompressZlib(byte[] compressedData)
        {
            // zlib compressed data contains a 2-byte header, so we need to skip it
            const int zlibHeaderSize = 2;

            using var inputStream = new MemoryStream(compressedData, zlibHeaderSize, compressedData.Length - zlibHeaderSize);
            using var deflateStream = new DeflateStream(inputStream, CompressionMode.Decompress);
            using var outputStream = new MemoryStream();
            deflateStream.CopyTo(outputStream);
            return outputStream.ToArray();
        }

        private static async Task<byte[]?> DownloadFilm(string filmPath)
        {
            using HttpClient client = new();
            // Add custom headers
            client.DefaultRequestHeaders.Add("X-343-Authorization-Spartan", HaloClient.SpartanToken);
            client.DefaultRequestHeaders.Add("343-clearance", HaloClient.ClearanceToken);

            try
            {
                // Attempt to download byte array from the URL
                byte[] data = await client.GetByteArrayAsync(filmPath);
                Console.WriteLine($"Downloaded {data.Length} chunk bytes successfully for {filmPath}.");
                return data;
            }
            catch (HttpRequestException e) when (e.StatusCode != HttpStatusCode.OK)
            {
                if (e.StatusCode != HttpStatusCode.NotFound)
                {
                    // Handle cases where the request is not successful. At this point, we're not super-picky
                    // Let's just re-initialize the application and try to get the data again.
                    Console.WriteLine($"Unauthorized request for {filmPath}: {e.Message}. Initializing application...");
                    bool appState = await InitializeApplication(); // Call your initialization function

                    if (appState)
                    {
                        // Retry the download
                        try
                        {
                            byte[] data = await client.GetByteArrayAsync(filmPath);
                            Console.WriteLine($"Downloaded {data.Length} chunk bytes successfully for {filmPath} after reinitialization.");
                            return data;
                        }
                        catch (HttpRequestException retryException)
                        {
                            Console.WriteLine($"Retry failed for {filmPath}: {retryException.Message}");
                            return null;
                        }
                    }
                    else
                    {
                        Console.WriteLine("Could not re-initialize the application.");
                        return null;
                    }
                }
                else
                {
                    throw new FileNotFoundException("The film chunk file was not found on the server.");
                }
            }
            catch (HttpRequestException e)
            {
                // Handle other request errors
                Console.WriteLine($"Request error for {filmPath}: {e.Message}");
                return null;
            }
        }

        private static async Task<List<Guid>> GetPlayerMatchIds(string xuid)
        {
            List<Guid> matchIds = [];
            int queryStart = 0;

            var tasks = new ConcurrentBag<Task<List<Guid>>>();

            // If EnableLooseMatchSearch is enabled, we need to also check that the
            // threshold for successful matches is not hit.
            while (true)
            {

                tasks.Add(GetMatchBatchAsync(xuid, queryStart, MatchesPerPage));

                queryStart += MatchesPerPage;

                if (tasks.Count == 4)
                {
                    var completedTasks = await Task.WhenAll(tasks);
                    tasks.Clear();

                    // Flatten the batches and add to the overall match list
                    foreach (var batch in completedTasks)
                    {
                        matchIds.AddRange(batch);
                    }

                    if (completedTasks.LastOrDefault()?.Count == 0)
                    {
                        // No more matches to fetch, break out of the loop
                        break;
                    }
                }
            }

            Console.WriteLine($"Ended indexing at {matchIds.Count} total matchmade games.");

            return matchIds;
        }

        private static async Task<List<Guid>> GetMatchBatchAsync(string xuid, int start, int count)
        {
            List<Guid> successfulMatches = [];
            List<(string xuid, int start, int count)> retryQueue = [];

            Console.WriteLine($"Getting {count} matches starting from index {start}...");

            var matches = await SafeAPICall(async () => await HaloClient.StatsGetMatchHistory($"xuid({xuid})", start, count, Den.Dev.Orion.Models.HaloInfinite.MatchType.All));

            if (matches.Response.Code == 200)
            {
                successfulMatches.AddRange(matches?.Result?.Results?.Select(item => item.MatchId) ?? []);
                Console.WriteLine($"Added {matches?.Result?.Results?.Count} matches.");
            }
            else
            {
                Console.WriteLine($"Error getting match stats through the search endpoint. Adding to retry queue. XUID: {xuid}, START: {start}, COUNT: {count}. Response code: {matches.Response.Code}. Response message: {matches.Response.Message}");
                retryQueue.Add((xuid, start, count));
            }

            // Process retry queue after processing successful requests
            foreach (var retryRequest in retryQueue)
            {
                await ProcessRetry(retryRequest, successfulMatches);
            }

            return successfulMatches;
        }

        private static async Task ProcessRetry((string xuid, int start, int count) retryRequest, List<Guid> successfulMatches)
        {
            var retryAttempts = 0;
            HaloApiResultContainer<MatchHistoryResponse, RawResponseContainer> retryMatches;

            do
            {
                retryMatches = await SafeAPICall(async () => await HaloClient.StatsGetMatchHistory($"xuid({retryRequest.xuid})", retryRequest.start, retryRequest.count, Den.Dev.Orion.Models.HaloInfinite.MatchType.All));

                if (retryMatches.Response.Code == 200)
                {
                    successfulMatches.AddRange(retryMatches?.Result?.Results?.Select(item => item.MatchId) ?? Enumerable.Empty<Guid>());
                    break; // Break the loop if successful
                }
                else
                {
                    Console.WriteLine($"Error getting match stats through the search endpoint. Retry index: {retryAttempts}. XUID: {retryRequest.xuid}, START: {retryRequest.start}, COUNT: {retryRequest.count}. Response code: {retryMatches.Response.Code}. Response message: {retryMatches.Response.Message}");
                    retryAttempts++;
                }
            } while (retryAttempts < 3); // Retry up to 3 times

            if (retryAttempts == 3)
            {
                // Log or handle the failure after 3 attempts
                Console.WriteLine($"Failed to retrieve matches after 3 attempts. XUID: {retryRequest.xuid}, START: {retryRequest.start}, COUNT: {retryRequest.count}");
            }
        }

        internal static async Task<bool> InitializeApplication()
        {
            var authResult = await InitializePublicClientApplication();
            if (authResult != null)
            {
                var result = await InitializeHaloClient(authResult);

                return result;
            }
            else
            {
                return false;
            }
        }

        internal static async Task<bool> InitializeHaloClient(AuthenticationResult authResult)
        {
            try
            {
                HaloAuthenticationClient haloAuthClient = new();
                XboxAuthenticationClient manager = new();

                var ticket = await manager.RequestUserToken(authResult.AccessToken) ?? await manager.RequestUserToken(authResult.AccessToken);

                if (ticket == null)
                {
                    Console.WriteLine("Failed to obtain Xbox user token.");
                    return false;
                }

                var haloTicketTask = manager.RequestXstsToken(ticket.Token);
                var extendedTicketTask = manager.RequestXstsToken(ticket.Token, false);

                var haloTicket = await haloTicketTask;
                var extendedTicket = await extendedTicketTask;

                if (haloTicket == null)
                {
                    Console.WriteLine("Failed to obtain Halo XSTS token.");
                    return false;
                }

                var haloToken = await haloAuthClient.GetSpartanToken(haloTicket.Token, 4);

                if (extendedTicket != null)
                {
                    XboxUserContext = extendedTicket;

                    HaloClient = new HaloInfiniteClient(haloToken.Token, extendedTicket.DisplayClaims.Xui[0].XUID, userAgent: $"{ApplicationName}/{ApplicationVersion}");

                    PlayerClearance? clearance = null;

                    clearance = (await SafeAPICall(async () => await HaloClient.SettingsActiveClearance(HaloInfiniteAPIRelease)))?.Result;

                    if (clearance != null && !string.IsNullOrWhiteSpace(clearance.FlightConfigurationId))
                    {
                        HaloClient.ClearanceToken = clearance.FlightConfigurationId;
                        Console.WriteLine($"Your clearance is {clearance.FlightConfigurationId} and it's set in the client.");
                        return true;
                    }
                    else
                    {
                        Console.WriteLine("Could not obtain the clearance.");
                        return false;
                    }
                }
                else
                {
                    Console.WriteLine("Extended ticket is null. Cannot authenticate.");
                    return false;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error initializing Halo client: {ex.Message}");
                return false;
            }
        }

        public static async Task<HaloApiResultContainer<T, RawResponseContainer>> SafeAPICall<T>(Func<Task<HaloApiResultContainer<T, RawResponseContainer>>> orionAPICall)
        {
            try
            {
                HaloApiResultContainer<T, RawResponseContainer> result = await orionAPICall();

                if (result != null && result.Response != null && result.Response.Code == 401)
                {
                    if (await InitializeApplication())
                    {
                        result = await orionAPICall();
                    }
                    else
                    {
                        Console.WriteLine("Could not reacquire tokens.");
                        return default;
                    }
                }

                return result;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to make Halo Infinite API call. {ex.Message}");
                return default;
            }
        }

        internal static async Task<AuthenticationResult> InitializePublicClientApplication()
        {
            var storageProperties = new StorageCreationPropertiesBuilder(CacheFileName, AppDomain.CurrentDomain.BaseDirectory).Build();

            var pcaBootstrap = PublicClientApplicationBuilder
                .Create(ClientId)
                .WithDefaultRedirectUri()
                .WithAuthority(AadAuthorityAudience.PersonalMicrosoftAccount);

            var pca = pcaBootstrap.Build();

            // This hooks up the cross-platform cache into MSAL
            var cacheHelper = await MsalCacheHelper.CreateAsync(storageProperties);
            cacheHelper.RegisterCache(pca.UserTokenCache);

            IAccount accountToLogin = (await pca.GetAccountsAsync()).FirstOrDefault();

            AuthenticationResult authResult = null;

            try
            {
                authResult = await pca.AcquireTokenSilent(Scopes, accountToLogin)
                                            .ExecuteAsync();
            }
            catch (MsalUiRequiredException)
            {
                try
                {
                    authResult = await pca.AcquireTokenInteractive(Scopes)
                                                .WithAccount(accountToLogin)
                                                .ExecuteAsync();
                }
                catch (MsalClientException ex)
                {
                    // Authentication was not successsful, we have no token.
                    Console.WriteLine($"Authentication was not successful. {ex.Message}");
                }
            }

            return authResult;
        }

        public static List<int> FindPatternPositions(byte[] data, byte[] pattern)
        {
            List<int> matchPositions = [];
            int dataBitLength = data.Length * 8;
            int patternBitLength = pattern.Length * 8;

            for (int bitPos = 0; bitPos <= dataBitLength - patternBitLength; bitPos++)
            {
                if (IsBitMatch(data, pattern, bitPos))
                {
                    matchPositions.Add(bitPos);
                }
            }
            return matchPositions;
        }

        public static byte[] ExtractBitsFromPosition(byte[] data, int startBitPosition, int bitLength, [CallerMemberName] string caller = "")
        {
            // Calculate the actual end bit position
            int endBitPosition = startBitPosition + bitLength - 1;

            // Validate input parameters
            if (startBitPosition < 0 || endBitPosition < 0 || startBitPosition >= data.Length * 8 || endBitPosition >= data.Length * 8 || startBitPosition > endBitPosition)
            {
                //throw new ArgumentOutOfRangeException("Bit positions are out of range or invalid.");
                Console.WriteLine($"[ERROR] Could not get the bits from position {startBitPosition} to bit length {bitLength}. Data length: {data.Length}. Caller: {caller}");
                return null;
            }

            // Calculate the byte offset and bit shift for the start position
            int startByteOffset = startBitPosition / 8;
            int startBitShift = startBitPosition % 8;

            // Calculate the byte offset and bit shift for the end position
            int endByteOffset = endBitPosition / 8;
            int endBitShift = endBitPosition % 8;

            // Calculate the number of bytes to extract
            int byteCount = endByteOffset - startByteOffset + 1;

            // Allocate the result array
            byte[] extractedData = new byte[byteCount];

            // Go byte by byte, shift and copy
            for (int i = 0; i < byteCount - 1; i++)
            {
                // Shift the current byte and take bits from the next byte if needed
                extractedData[i] = (byte)((data[startByteOffset + i] << startBitShift) | (data[startByteOffset + i + 1] >> (8 - startBitShift)));
            }

            // Handle the last byte (since it has no next byte to pull from)
            extractedData[byteCount - 1] = (byte)(data[startByteOffset + byteCount - 1] << startBitShift);

            // Mask the last byte to only include bits up to endBitShift
            extractedData[byteCount - 1] &= (byte)(0xFF << (7 - endBitShift) >> (7 - endBitShift));

            return extractedData;
        }

        public static bool IsBitMatch(byte[] data, byte[] pattern, int bitOffset)
        {
            // Calculates the number of whole bytes to skip.
            // We divide bitOffset by 8 because there are 8 bits per byte.
            int byteOffset = bitOffset / 8;

            // Calculates how far into the byte (number of bits) we need to start.
            // It's the remainder when bitOffset is divided by 8, giving the bit position within the byte.
            int bitShift = bitOffset % 8;

            // On the above, a good example to visualize the behavior:
            // If bitOffset = 10, byteOffset = 1 (skip 1 full byte) and bitShift = 2 (start at the 3rd bit in the second byte - we skip 2).

            // We now iterate through every byte in the pattern that is given to
            // us when the function is called.
            for (int i = 0; i < pattern.Length; i++)
            {
                // Get the data byte that alligns with the current
                // pattern byte and shifts the bits to the left by the
                // calculated bit shift value earlier.
                byte dataByte = (byte)(data[byteOffset + i] << bitShift);

                // If bitShift > 0, include bits from the next byte. This is
                // important for scenarios where, for example, we're shifting
                // by 3 bits, meaning that part of the data will come from the
                // next byte.
                if (byteOffset + i + 1 < data.Length && bitShift > 0)
                {
                    // Shifts the next byte to the right by the delta between 8
                    // and the calcualted bit shift value, aligning it with the
                    // remaining part of the data byte.
                    // Note: bitwise OR (|=) is used to combine the shifted parts
                    // so that we can perform a full byte comparison.
                    dataByte |= (byte)(data[byteOffset + i + 1] >> (8 - bitShift));
                }

                // Compare dataByte with the current byte in the pattern
                if (dataByte != pattern[i])
                {
                    // Not matching at position. No point in
                    // continuing.
                    return false;
                }
            }

            // All bits match
            return true;
        }

        public static string ConvertBytesToText(byte[] byteArray)
        {
            ArgumentNullException.ThrowIfNull(byteArray);

            if (byteArray.Length == 0)
            {
                return string.Empty; // Return an empty string for an empty array.
            }

            // Step 1: Trim trailing double 0x00 bytes
            int endIndex = byteArray.Length;
            while (endIndex > 1 && byteArray[endIndex - 1] == 0x00 && byteArray[endIndex - 2] == 0x00)
            {
                endIndex -= 1;
            }

            // Step 2: Trim leading 0x00 bytes
            int startIndex = 0;
            while (startIndex < endIndex && byteArray[startIndex] == 0x00)
            {
                startIndex++;
            }

            // Step 3: Extract the remaining bytes
            int remainingLength = endIndex - startIndex;
            if (remainingLength % 2 != 0)
            {
                Console.WriteLine("Byte array length must be even for UTF-16 encoding.");
                Console.WriteLine(byteArray.Select(b => b.ToString("X2")));
                return string.Empty;
            }

            byte[] trimmedBytes = new byte[remainingLength];
            Array.Copy(byteArray, startIndex, trimmedBytes, 0, remainingLength);

            // Step 4: Convert to string
            string result = Encoding.Unicode.GetString(trimmedBytes);

            // Step 5: Trim trailing null characters (0x00)
            result = result.TrimEnd('\0');

            // Step 6: Ensure only one trailing null character if there were two in the original byte array
            if (remainingLength > 0 && endIndex - startIndex > 0 && byteArray[endIndex - 1] == 0x00 && byteArray[endIndex - 2] == 0x00)
            {
                if (result.EndsWith("\0"))
                {
                    result = result.Substring(0, result.Length - 1);
                }
            }

            return result;
        }

        public static long ConvertBytesToInt64(byte[] byteArray, int startIndex = 0)
        {
            ArgumentNullException.ThrowIfNull(byteArray);

            if (byteArray.Length < startIndex + 8)
            {
                throw new ArgumentException("The byte array must contain at least 8 bytes starting from the specified index.");
            }

            return BitConverter.ToInt64(byteArray, startIndex);
        }

        public static List<GameEvent> ProcessFilmTimelineData(byte[] data, byte[] pattern)
        {
            List<GameEvent> events = [];

            List<int> patternPositions = FindPatternPositions(data, pattern);
            foreach (var patternPosition in patternPositions)
            {
                // A whole game event is 60 bytes, let's extract it.
                var eventBinaryContent = ExtractBitsFromPosition(data, patternPosition, 60 * 8);

                if (eventBinaryContent != null)
                {
                    var gameEvent = ParseGameEvent(eventBinaryContent);
                    if (gameEvent != null)
                    {
                        events.Add(gameEvent);
                    }
                }
                else
                {
                    Console.WriteLine("[ERROR] Event binary content is null.");
                }
            }

            return events;
        }

        public static Dictionary<long, string> ProcessFilmBootstrapData(byte[] data, byte[] pattern)
        {
            List<int> patternPositions = FindPatternPositions(data, pattern);

            Dictionary<long, string> players = [];

            foreach (int patternPosition in patternPositions)
            {
                int xuidStartPosition = patternPosition - 8 * 8;
                byte[] xuid = ExtractBitsFromPosition(data, xuidStartPosition, 8 * 8);

                if (xuid != null)
                {
                    var convertedXuid = ConvertBytesToInt64(xuid);

                    // We make sure that XUIDs are not some weird values.
                    if (convertedXuid > 0)
                    {
                        int prePatternPosition = xuidStartPosition - 21 * 8;
                        var bytePrefixValidated = AreAllBytesZero(data, prePatternPosition, 21 * 8);

                        if (bytePrefixValidated)
                        {
                            Console.WriteLine($"Detected gamertag extraction position: {prePatternPosition - 32 * 8}");
                            byte[] gamertagData = ExtractBitsFromPosition(data, prePatternPosition - 32 * 8, 32 * 8);

                            if (gamertagData != null)
                            {
                                var gamertag = ConvertBytesToText(gamertagData);
                                Console.WriteLine($"Gamertag: {gamertag}");

                                if (gamertag != null && !string.IsNullOrWhiteSpace(gamertag))
                                {
                                    players.TryAdd(ConvertBytesToInt64(xuid), gamertag);
                                }
                            }
                            else
                            {
                                Console.WriteLine("[ERROR] Gamertag data is null.");
                            }
                        }
                    }
                }
                else
                {
                    Console.WriteLine("[ERROR] XUID data is null.");
                }
            }

            return players;
        }

        public static bool AreAllBytesZero(byte[] data, int bitPosition, int bitCount)
        {
            int startByteOffset = bitPosition / 8;
            int startBitOffset = bitPosition % 8;

            // Check if the starting byte is valid
            if (startByteOffset < 0 || startByteOffset >= data.Length)
            {
                return false;
            }

            // Check bits in the starting byte
            if (startBitOffset > 0)
            {
                int bitsToCheck = Math.Min(8 - startBitOffset, bitCount);
                byte startByteMask = (byte)((0xFF >> startBitOffset) & (0xFF << (8 - (startBitOffset + bitsToCheck))));
                if ((data[startByteOffset] & startByteMask) != 0x00)
                {
                    return false;
                }
                bitCount -= bitsToCheck;
                startByteOffset++;
            }

            // Check full bytes in the middle
            while (bitCount >= 8 && startByteOffset < data.Length)
            {
                if (data[startByteOffset] != 0x00)
                {
                    return false;
                }
                startByteOffset++;
                bitCount -= 8;
            }

            // Check bits in the ending byte
            if (bitCount > 0 && startByteOffset < data.Length)
            {
                byte endByteMask = (byte)(0xFF << (8 - bitCount));
                if ((data[startByteOffset] & endByteMask) != 0x00)
                {
                    return false;
                }
            }

            return true;
        }

        public static GameEvent ParseGameEvent(byte[] data)
        {
            var gameEvent = new GameEvent();

            // Extract the 16-character UTF-16 gamertag (32 bytes)
            byte[] gamertagBytes = ExtractBitsFromPosition(data, 0, 32 * 8);

            if (gamertagBytes != null)
            {
                gameEvent.Gamertag = Encoding.Unicode.GetString(gamertagBytes).Trim('\0');

                // Extract the type hint (1 byte)
                byte typeHint = ExtractBitsFromPosition(data, 32 * 8 + 15 * 8, 8)[0];

                if (typeHint != null)
                {
                    gameEvent.TypeHint = typeHint;

                    // Extract the timestamp (4 bytes)
                    byte[] timestampBytes = ExtractBitsFromPosition(data, 32 * 8 + 15 * 8 + 8, 4 * 8);

                    if (timestampBytes != null)
                    {
                        Array.Reverse(timestampBytes);
                        gameEvent.Timestamp = BitConverter.ToUInt32(timestampBytes, 0);

                        // Extract the is medal (1 byte)
                        byte isMedal = ExtractBitsFromPosition(data, 32 * 8 + 15 * 8 + 8 + 4 * 8 + 3 * 8, 8)[0];
                        gameEvent.IsMedal = isMedal;

                        // Extract the medal type (1 byte)
                        byte medalType = ExtractBitsFromPosition(data, 32 * 8 + 15 * 8 + 8 + 4 * 8 + 3 * 8 + 8 + 3 * 8, 8)[0];
                        gameEvent.MedalType = medalType;

                        return gameEvent;
                    }
                    else
                    {
                        Console.WriteLine("[ERROR] Timestamp bytes are null when parsing event.");
                    }
                }
                else
                {
                    Console.WriteLine("[ERROR] Type hint bytes are null when parsing event.");
                }
            }
            else
            {
                Console.WriteLine("[ERROR] Gamertag bytes are null when parsing event.");
            }

            return null;
        }
    }
}
