namespace OpenSpartan.FilmEventExtractor.Models
{
    public class GameEvent
    {
        public string Gamertag { get; set; }
        public byte TypeHint { get; set; }
        public uint Timestamp { get; set; }
        public byte IsMedal { get; set; }
        public byte MedalType { get; set; }
    }
}
