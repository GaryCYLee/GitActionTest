using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace PodTest
{
    class Program
    {
        static void Main(string[] args)
        {
            HttpWebRequest request = GetHttpRequest();

            // Sample JSON payload
            string jsonPayload = "{\"key\":\"value\"}";

            // Write the payload to the request stream
            using (var streamWriter = new StreamWriter(request.GetRequestStream()))
            {
                streamWriter.Write(jsonPayload);
                streamWriter.Flush();
                streamWriter.Close();
            }

            try
            {
                // Get the response
                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                {
                    using (var streamReader = new StreamReader(response.GetResponseStream()))
                    {
                        string result = streamReader.ReadToEnd();
                        Console.WriteLine("Response: " + result);
                    }
                }
            }
            catch (WebException ex)
            {
                // Handle any errors
                using (var errorResponse = (HttpWebResponse)ex.Response)
                {
                    using (var streamReader = new StreamReader(errorResponse.GetResponseStream()))
                    {
                        string errorText = streamReader.ReadToEnd();
                        Console.WriteLine("Error: " + errorText);
                    }
                }
            }
        }
        public static HttpWebRequest GetHttpRequest()
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            string urlWithProtocol = "https://ha2xes.beta.manage.trendmicro.com/officescan/osfwebapp/api/v2/SystemCall/scid/OSF_SYSCALL_ONREGISTER/scc/OSF_IPRODUCT_IAC";
            HttpWebRequest request = (HttpWebRequest)System.Net.WebRequest.Create(urlWithProtocol);

            request.UserAgent = "PodTest";
            request.Timeout = 15 * 60 * 1000; // [ToDo] to be a config?
            request.Method = System.Net.Http.HttpMethod.Post.ToString();
            request.ContentType = "application/json; charset=utf-8";
            request.Headers.Add(System.Net.HttpRequestHeader.AcceptEncoding, "gzip, deflat");
            request.ClientCertificates.Add(GetOsfKeyPair());
            request.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(CertificateValidationCallback);
            return request;
        }
        public static X509Certificate2 GetOsfKeyPair()
        {
            X509Certificate2 osfCert = new X509Certificate2();
            try
            {
                const string privateKeyStore = "OfcOSF";
                X509Store store = new X509Store(privateKeyStore, StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection certs = store.Certificates.Find(X509FindType.FindBySubjectName, "OfcOSFWebApp", false);
                store.Close();
                if (certs.Count > 1)
                {
                    Console.WriteLine("There are more the one certificate, choose first.");
                }
                if (certs.Count < 1)
                {
                    throw new System.Exception("Can't find certificate");
                }
                osfCert = certs[0];
            }
            catch (System.Exception ex)
            {
                Console.WriteLine("Exception: {0}", ex.Message);
            }
            return osfCert;
        }
        private static bool CertificateValidationCallback(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            bool result = true;

            if (sslPolicyErrors != SslPolicyErrors.None)
            {
                Console.WriteLine("Certificate error: {0}", sslPolicyErrors);

                if ((sslPolicyErrors & SslPolicyErrors.RemoteCertificateChainErrors) != 0)
                {
                    for (int i = 0; i < chain.ChainStatus.Length; i++)
                    {
                        Console.WriteLine($"ChainStatus[{i}].Status: {chain.ChainStatus[i].Status}");
                        Console.WriteLine($"ChainStatus[{i}].StatusInformation: {chain.ChainStatus[i].StatusInformation}");
                    }
                }

                // According to the instruction given by OSF architect and OSF WSI security designer on 2018/1/8, ignore OSCE server certificate chain errors caused by its being self-signed
                result = (sslPolicyErrors == SslPolicyErrors.RemoteCertificateChainErrors) ? true : false;

                if (!result)
                {
                    X509Certificate2 certificate2 = certificate as X509Certificate2 ?? new X509Certificate2(certificate);
                    try
                    {
                        Console.WriteLine($"Verify certificate with PeerTrust");
                        result = true;
                        //System.IdentityModel.Selectors.X509CertificateValidator.PeerTrust.Validate(certificate2);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Untrusted certificate. cert.Subject:({certificate2.Subject}). cert.Issuer:({certificate2.Issuer}). Detail info:{ex.ToString()}");
                        result = false;
                    }
                }
            }
            return result;
        }
    }
}
