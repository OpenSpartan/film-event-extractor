﻿using Den.Dev.Orion.Authentication;
using Den.Dev.Orion.Core;
using Den.Dev.Orion.Models;
using Den.Dev.Orion.Models.HaloInfinite;
using Den.Dev.Orion.Models.Security;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Extensions.Msal;
using System;
using System.Collections.Concurrent;
using System.IO.Compression;
using System.Text;

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

        internal static readonly byte[] PlayerIdentificationPattern = { 0x2D, 0xC0 };

        internal static readonly int MatchesPerPage = 25;

        internal static XboxTicket XboxUserContext { get; set; }

        internal static HaloInfiniteClient HaloClient { get; set; }

        static async Task Main(string[] args)
        {
            Console.WriteLine($"{ApplicationName} ({ApplicationVersion})");
            Console.WriteLine("Authenticating...");
            var authResult = await InitializeApplication();
            if (authResult)
            {
                // Authentication was successful.
                Console.WriteLine("Authentication successful.");

                var matchIds = await GetPlayerMatchIds(XboxUserContext.DisplayClaims.Xui[0].XUID);

                if (matchIds != null && matchIds.Count > 0)
                {
                    // We have matches - let's get the films for each.
                    foreach (var matchId in matchIds)
                    {
                        var filmMetadata = await SafeAPICall(async () => await HaloClient.HIUGCDiscoverySpectateByMatchId(matchId.ToString()));
                        if (filmMetadata != null && filmMetadata.Result != null)
                        {
                            // Individual chunks contain player information that we do not have anywhere else. Let's try and parse it out.
                            var playerTagChunk = filmMetadata.Result.CustomData.Chunks.First(x => x.ChunkType == 1);

                            // General metadata chunk always has chunk type of 3.
                            var generalMetadataChunk = filmMetadata.Result.CustomData.Chunks.First(x => x.ChunkType == 3);

                            if (playerTagChunk != null && generalMetadataChunk != null)
                            {
                                Console.WriteLine($"Processing {playerTagChunk.FileRelativePath} for {matchId}...");

                                var url = $"{filmMetadata.Result.BlobStoragePathPrefix}{playerTagChunk.FileRelativePath.Replace("/", string.Empty)}";
                                Console.WriteLine($"Downloading film chunk from {url}");

                                var compressedPlayerData = await DownloadFilm(url);
                                var uncompressedPlayerData = UncompressZlib(compressedPlayerData);

                                var players = ProcessFilmBootstrapData(uncompressedPlayerData, PlayerIdentificationPattern);
                                foreach (var player in players)
                                {
                                    Console.WriteLine($"{player.Key} - {player.Value}");
                                }

                                var compressedMetadata = await DownloadFilm($"{filmMetadata.Result.BlobStoragePathPrefix}{generalMetadataChunk.FileRelativePath.Replace("/", string.Empty)}");
                                var uncompressedMetadata = UncompressZlib(compressedMetadata);

                                foreach (var player in players)
                                {
                                    Console.WriteLine($"Searching for events for {player.Value} ({string.Join(" ", InsertZeroBytes(Encoding.UTF8.GetBytes(player.Value)).Select(b => b.ToString("X2")))})...");
                                    //var searchPattern = InsertZeroBytes(Encoding.UTF8.GetBytes(player.Value));
                                    var data = ProcessFilmTimelineData(uncompressedMetadata, InsertZeroBytes(Encoding.UTF8.GetBytes(player.Value)));
                                }
                                //if (compressedPlayerData != null && compressedMetadata != null)
                                //{
                                //    Console.WriteLine($"We have both required chunks for {matchId}. Processing...");
                                //}
                            }
                        }
                        else
                        {
                            Console.WriteLine($"Could not get film metadata for match {matchId}");
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

        public static byte[] InsertZeroBytes(byte[] data)
        {
            // Define zero byte to insert
            byte zeroByte = 0x00;

            // Calculate the length of the new byte array
            int newSize = data.Length * 2 - 1;
            byte[] result = new byte[newSize];

            // Insert characters and zero bytes
            int resultIndex = 0;
            for (int i = 0; i < data.Length; i++)
            {
                result[resultIndex++] = data[i];
                if (i < data.Length - 1) // Avoid appending zero byte after the last character
                {
                    result[resultIndex++] = zeroByte;
                }
            }

            return result;
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
            using (HttpClient client = new())
            {
                // Add custom headers
                client.DefaultRequestHeaders.Add("X-343-Authorization-Spartan", HaloClient.SpartanToken);
                client.DefaultRequestHeaders.Add("343-clearance", HaloClient.ClearanceToken);

                try
                {
                    // Download byte array from the URL
                    byte[] data = await client.GetByteArrayAsync(filmPath);
                    Console.WriteLine($"Downloaded {data.Length} chunk bytes successfully for {filmPath}.");

                    return data;
                }
                catch (HttpRequestException e)
                {
                    Console.WriteLine($"Request error for {filmPath}: {e.Message}");
                    return null;
                }
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

        public static byte[] ExtractBitsFromPosition(byte[] data, int startBitPosition, int bitLength)
        {
            // Calculate the actual end bit position
            int endBitPosition = startBitPosition + bitLength - 1;

            // Validate input parameters
            if (startBitPosition < 0 || endBitPosition < 0 || startBitPosition >= data.Length * 8 || endBitPosition >= data.Length * 8 || startBitPosition > endBitPosition)
            {
                throw new ArgumentOutOfRangeException("Bit positions are out of range or invalid.");
            }

            // Calculate the byte offset and bit shift for the start position
            int startByteOffset = startBitPosition / 8;
            int startBitShift = startBitPosition % 8;

            // Calculate the byte offset and bit shift for the end position
            int endByteOffset = endBitPosition / 8;
            int endBitShift = endBitPosition % 8;

            // Calculate the number of bytes to extract
            int byteCount = endByteOffset - startByteOffset + 1;

            // If there's no bit shift, we can return from the byte offset onward
            if (startBitShift == 0 && endBitShift == 0)
            {
                byte[] result = new byte[byteCount];
                Array.Copy(data, startByteOffset, result, 0, byteCount);
                return result;
            }

            // Otherwise, we need to shift the bits manually
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
            extractedData[byteCount - 1] &= (byte)(0xFF << (8 - endBitShift));

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
            if (byteArray == null)
            {
                throw new ArgumentNullException(nameof(byteArray));
            }

            return Encoding.UTF8.GetString(byteArray);
        }

        public static long ConvertBytesToInt64(byte[] byteArray, int startIndex = 0)
        {
            if (byteArray == null)
            {
                throw new ArgumentNullException(nameof(byteArray));
            }

            if (byteArray.Length < startIndex + 8)
            {
                throw new ArgumentException("The byte array must contain at least 8 bytes starting from the specified index.");
            }

            return BitConverter.ToInt64(byteArray, startIndex);
        }

        public static Dictionary<long, string> ProcessFilmTimelineData(byte[] data, byte[] pattern)
        {
            List<int> patternPositions = FindPatternPositions(data, pattern);
            foreach (var patternPosition in patternPositions)
            {
                Console.WriteLine(patternPosition.ToString());
            }
            //Dictionary<long, string> players = [];

            //foreach (int patternPosition in patternPositions)
            //{
            //    int xuidStartPosition = patternPosition - 8 * 8;
            //    byte[] xuid = ExtractBitsFromPosition(data, xuidStartPosition, 8 * 8);

            //    int prePatternPosition = xuidStartPosition - 22 * 8;
            //    var bytePrefixValidated = AreAllBytesZero(data, prePatternPosition, 22);

            //    if (bytePrefixValidated)
            //    {
            //        byte[] gamertagData = ExtractBitsFromPosition(data, prePatternPosition - 32 * 8, 32 * 8);

            //        players.TryAdd(ConvertBytesToInt64(xuid), ConvertBytesToText(gamertagData));
            //    }
            //}

            return null;
        }
        static byte[] RemoveZeroBytes(byte[] inputArray)
        {
            // Create a temporary array to store non-zero bytes
            byte[] tempArray = new byte[inputArray.Length];
            int count = 0;

            // Copy non-zero bytes to the temporary array
            foreach (byte b in inputArray)
            {
                if (b != 0)
                {
                    tempArray[count++] = b;
                }
            }

            // Create the final array with the correct size
            byte[] resultArray = new byte[count];
            Array.Copy(tempArray, 0, resultArray, 0, count);

            return resultArray;
        }

        public static Dictionary<long, string> ProcessFilmBootstrapData(byte[] data, byte[] pattern)
        {
            List<int> patternPositions = FindPatternPositions(data, pattern);

            Dictionary<long, string> players = [];

            foreach (int patternPosition in patternPositions)
            {
                int xuidStartPosition = patternPosition - 8 * 8;
                byte[] xuid = ExtractBitsFromPosition(data, xuidStartPosition, 8 * 8);
                var convertedXuid = ConvertBytesToInt64(xuid);

                // We make sure that XUIDs are not some weird values.
                if (convertedXuid > 0)
                {
                    int prePatternPosition = xuidStartPosition - 22 * 8;
                    var bytePrefixValidated = AreAllBytesZero(data, prePatternPosition, 22 * 8);

                    if (bytePrefixValidated)
                    {
                        byte[] gamertagData = RemoveZeroBytes(ExtractBitsFromPosition(data, prePatternPosition - 32 * 8, 32 * 8));

                        players.TryAdd(ConvertBytesToInt64(xuid), ConvertBytesToText(gamertagData));
                    }
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
    }
}