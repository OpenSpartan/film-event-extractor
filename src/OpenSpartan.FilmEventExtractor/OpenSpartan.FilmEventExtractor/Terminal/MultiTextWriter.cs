using System.Text;

namespace OpenSpartan.FilmEventExtractor.Terminal
{
    class MultiTextWriter : TextWriter
    {
        private readonly TextWriter _consoleWriter;
        private readonly TextWriter _logFileWriter;

        public MultiTextWriter(TextWriter consoleWriter, TextWriter logFileWriter)
        {
            _consoleWriter = consoleWriter;
            _logFileWriter = logFileWriter;
        }

        public override Encoding Encoding => _consoleWriter.Encoding;

        // Override the WriteLine method to write to both the console and log file
        public override void WriteLine(string value)
        {
            _consoleWriter.WriteLine(value);
            _logFileWriter.WriteLine(value);
        }

        // Override the Write method to handle cases when Console.Write is used
        public override void Write(string value)
        {
            _consoleWriter.Write(value);
            _logFileWriter.Write(value);
        }
    }
}
