using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.IO.Compression;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.Threading;

namespace ConsoleApp1
{
    class Program
    {
        public static void WriteEventLog(string log, EventLogEntryType type, int eventId)
        {
            string logName = "Application";
            string sourceName = "LogAccessor";

            if (!EventLog.SourceExists(sourceName))
            {
                EventLog.CreateEventSource(sourceName, logName);
            }

            using (EventLog eventLog = new EventLog(logName))
            {
                eventLog.Source = sourceName;
                eventLog.WriteEntry(log, type, eventId);
            }
        }
        static void PeriodicFlush()
        {
            Thread.Sleep(10000);
            return;
        }
        static async Task Main()
        {
            Thread t_periodFlush = new Thread(PeriodicFlush);
            t_periodFlush.Start();
            if (t_periodFlush.IsAlive)
            {
                t_periodFlush.Join();
            }

            string ss = ReadFileContent("C:\\Users\\gary_cy_lee\\Downloads\\13e07df8-ddc9-4484-84d1-0185407edef7_2021-12-14T14_21_40.498Z.log");
            AddFile();
            string apiUrl = "https://logreceiver-aws-us-east-1.stg.sae.visionone.trendmicro.com/api/v2/detection_log/sao";
            string token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJjaWQiOiIwMDAwMDAxIiwiY3BpZCI6ImNsciIsIml0IjoxNTk0MzAwOTg1LCJwbCI6IiIsInBwaWQiOiJzYW8iLCJ1aWQiOiIifQ.TnT2mh_boZowjrFrDKlC4ldRGdGIoi2KocIcIf5QN7DMklGyRrMYW9S1BKqzuB5lbt8DAFWGr7zX6TIjsREjokjZnpRD2gIz6qO14OEBzMiiSxCf7_cNE0yNXNUchLCxTVM1FOd1Cj734UcDT4R9ttk2EQBr7wQ6yBygXIdIqkzKGUx2n0eRFgKhw6JPAZXNFWZNPedUSFrEfWgFTc9ZTGokoQ8VFhNWNKMf4pJiSJ-g6YfSNLMiREmzK0Y58n7JKeiSTnR5QrYg1qSqy2QijE7nkR7U8sR9rt89ktzSsBGAl3TLi6e59vxcF_Emt2BsIBfKASHdSqmfAD6haUKggrGYNpjIXxpJ2ZZvBXJwPRBo822gUFegKDagNu6B7NVOgd77OhQ2L6jETDBzWmrmVsg0EoMcaCqsAsWgMbTbuq9cICM1J9dfSLfz0-wnWYRIFOijr0tQ5V0HLkXODTx8c5RrPs4A6EyatzA1ivNfKH69th_CGid47UR-DFz6D9IsPDHjUI0I2rl5K4jv60aRTqZDK49fhxFy7Geuam_eEWkyEKl5vwF8JK14bL1c0Hd4BFKnefob1boNazf7HMYkSHMzGIN4iFZ2PEekSSwa3poks0atFT1dpcWSb3nByXKxkxKEaV8iZ-29oMA6ju_4vVuvmYmcQYZwoy_qtVLobh8";
            string filePath = @"C:\Users\gary_cy_lee\Downloads\sao_detection_log.log.gz";

            using (HttpClient client = new HttpClient())
            {
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
                List<String> LS = new List<string>
                {
                    "{\"AAA\":\"DDD\"}",
                    "{\"BBB\":\"EEE\"}",
                    "{\"BBB\":\"EEE\"}",
                    "{\"CCC\":\"FFF\"}"
                };

                byte[] fileData = GZipByte(filePath);

                StreamContent streamContent = new StreamContent(new MemoryStream(fileData));
                streamContent.Headers.ContentType = new MediaTypeHeaderValue("application/json");
                streamContent.Headers.ContentEncoding.Add("gzip");
                HttpResponseMessage response = await client.PostAsync(apiUrl, streamContent);

                if (response.IsSuccessStatusCode)
                {
                    string result = await response.Content.ReadAsStringAsync();
                    Console.WriteLine("Request successful. Response:");
                    Console.WriteLine(result);
                }
                else
                {
                    Console.WriteLine("Request failed. Status Code: " + response.StatusCode);
                }
            }
        }
        static string ReadFileContent(string filePath)
        {
            try
            {
                string content = File.ReadAllText(filePath);
                return content;
            }
            catch (Exception ex)
            {
                return "";
            }
        }
        protected static byte[] GZipByte(string content)
        {
            byte[] buff = Encoding.UTF8.GetBytes(content);
            using (MemoryStream ms = new MemoryStream())
            {
                using (GZipStream gzip = new GZipStream(ms, CompressionMode.Compress))
                {
                    gzip.Write(buff, 0, buff.Length);
                }

                return ms.ToArray();
            }
        }
        static void AddFile()
        {
            List<String> LS = new List<string>
            {
                "{\"AAA\":\"DDD\"}",
                "{\"BBB\":\"EEE\"}",
                "{\"BBB\":\"EEE\"}",
                "{\"CCC\":\"FFF\"}"
            };
            int a = LS.Count;
            using (Stream stream = new MemoryStream())
            {
                IFormatter formatter = new BinaryFormatter();

                formatter.Serialize(stream, LS);
                Console.WriteLine(stream.Length);
            }
            string combinedText = string.Join("", LS);

            string uniqueFileName = $"{Guid.NewGuid()}_{DateTime.UtcNow:yyyy-MM-ddTHH_mm_ss.fffZ}.log";
            string directoryPath = AppDomain.CurrentDomain.BaseDirectory + "XLogR";
            if (!Directory.Exists(directoryPath))
            {
                Directory.CreateDirectory(directoryPath);
            }
            string filePath = Path.Combine(directoryPath, uniqueFileName);

            File.WriteAllText(filePath, combinedText);

            Console.WriteLine("log：" + filePath);

            string compressedFileName = Path.ChangeExtension(filePath, ".gz");
            CompressFile(filePath, compressedFileName);
            if (File.Exists(filePath))
            {
                File.Delete(filePath);
            }
            Console.WriteLine("gz：" + compressedFileName);
        }

        static void CompressFile(string sourceFile, string compressedFile)
        {
            using (FileStream sourceStream = new FileStream(sourceFile, FileMode.Open))
            using (FileStream compressedStream = File.Create(compressedFile))
            using (GZipStream compressionStream = new GZipStream(compressedStream, CompressionMode.Compress))
            {
                sourceStream.CopyTo(compressionStream);
            }
        }
    }
}
