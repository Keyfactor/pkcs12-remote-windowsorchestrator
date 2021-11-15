// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

using Newtonsoft.Json;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;

using Keyfactor.Extensions.Orchestrator.PKCS12.RemoteHandlers;

namespace Keyfactor.Extensions.Orchestrator.PKCS12
{
    internal class PKCS12Store
    {
        private const string NO_EXTENSION = "noext";
        private const string FULL_SCAN = "fullscan";

        const string BEG_DELIM = "-----BEGIN CERTIFICATE-----";
        const string END_DELIM = "-----END CERTIFICATE-----";
        const string FILE_NAME_REPL = "||FILE_NAME_HERE||";

        static Mutex mutex = new Mutex(false, "ModifyStore");

        internal enum ServerTypeEnum
        {
            Linux,
            Windows
        }

        internal string Server { get; set; }
        internal string ServerId { get; set; }
        internal string ServerPassword { get; set; }
        internal string StorePath { get; set; }
        internal string StoreFileName { get; set; }
        internal string StorePassword { get; set; }
        internal IRemoteHandler SSH { get; set; }
        internal ServerTypeEnum ServerType { get; set; }
        internal List<string> DiscoveredStores { get; set; }

        internal string UploadFilePath { get; set; }


        internal PKCS12Store(string server, string serverId, string serverPassword, string storeFileAndPath, string storePassword)
        {
            Server = server;
            SplitStorePathFile(storeFileAndPath);
            ServerId = serverId;
            ServerPassword = serverPassword ?? string.Empty;
            StorePassword = storePassword;
            ServerType = StorePath.Substring(0, 1) == "/" ? ServerTypeEnum.Linux : ServerTypeEnum.Windows;
            UploadFilePath = ApplicationSettings.UseSeparateUploadFilePath && ServerType == ServerTypeEnum.Linux ? ApplicationSettings.SeparateUploadFilePath : StorePath;
        }

        internal void Initialize()
        {
            if (ServerType == ServerTypeEnum.Linux)
                SSH = new SSHHandler(Server, ServerId, ServerPassword);
            else
                SSH = new WinRMHandler(Server);

            SSH.Initialize();
        }

        internal void Terminate()
        {
            if (SSH != null)
                SSH.Terminate();
        }

        //internal bool DoesCertificateAliasExist(string alias)
        //{
        //    string keyToolCommand = $"{KeytoolPath}keytool -list -keystore '{StorePath + StoreFileName}' -alias '{alias}' {FormatStorePassword()}";
        //    string result = SSH.RunCommand(keyToolCommand, null, ServerType == ServerTypeEnum.Linux && ApplicationSettings.UseSudo, StorePassword == null ? null : new string[] { StorePassword });
        //    return !result.Contains("not exist");
        //}


        internal List<X509Certificate2Collection> GetCertificateChains()
        {
            List<X509Certificate2Collection> certificateChains = new List<X509Certificate2Collection>();

            byte[] byteContents = SSH.DownloadCertificateFile(StorePath + StoreFileName);
            Pkcs12Store store = new Pkcs12Store();
            
            using (MemoryStream stream = new MemoryStream(byteContents))
            {
                store = new Pkcs12Store(stream, StorePassword.ToCharArray());
            }

            foreach(string alias in store.Aliases)
            {
                X509Certificate2Collection chain = new X509Certificate2Collection();
                X509CertificateEntry[] entries;

                if (store.IsKeyEntry(alias))
                {
                    entries = store.GetCertificateChain(alias);
                }
                else
                {
                    X509CertificateEntry entry = store.GetCertificate(alias);
                    entries = new X509CertificateEntry[] { entry };
                }

                foreach(X509CertificateEntry entry in entries)
                {
                    X509Certificate2 cert = new X509Certificate2(entry.Certificate.GetEncoded());
                    cert.FriendlyName = alias;
                    chain.Add(cert);
                }

                certificateChains.Add(chain);
            }

            return certificateChains;
        }

        //internal List<string> GetCertificateChainForAlias(string alias)
        //{
        //    List<string> certChain = new List<string>();
        //    string keyToolCommand = $"{KeytoolPath}keytool -list -rfc -keystore '{StorePath + StoreFileName}' {FormatStorePassword()} -alias '{alias}'";
        //    string result = SSH.RunCommand(keyToolCommand, null, ServerType == ServerTypeEnum.Linux && ApplicationSettings.UseSudo, StorePassword == null ? null : new string[] { StorePassword });

        //    if (!result.Contains(BEG_DELIM))
        //        return certChain;

        //    int chainLength = GetChainLength(result);
        //    for (int i = 0; i < chainLength; i++)
        //    {
        //        certChain.Add(result.Substring(result.IndexOf(BEG_DELIM), result.IndexOf(END_DELIM) - result.IndexOf(BEG_DELIM) + END_DELIM.Length));
        //        result = result.Substring(result.IndexOf(END_DELIM) + END_DELIM.Length);
        //    }

        //    return certChain;
        //}

        //internal void DeleteCertificateByAlias(string alias)
        //{
        //    string keyToolCommand = $"{KeytoolPath}keytool -delete -alias '{alias}' -keystore '{StorePath + StoreFileName}' {FormatStorePassword()}";

        //    try
        //    {
        //        mutex.WaitOne();
        //        string result = SSH.RunCommand(keyToolCommand, null, ServerType == ServerTypeEnum.Linux && ApplicationSettings.UseSudo, StorePassword == null ? null : new string[] { StorePassword });
        //    }
        //    catch (Exception ex)
        //    {
        //        throw new PKCS12Exception($"Error attempting to remove certficate for store path={StorePath}, file name={StoreFileName}.", ex);
        //    }
        //    finally
        //    {
        //        mutex.ReleaseMutex();
        //    }
        //}

        //internal void CreateCertificateStore(string storePath, string storePassword)
        //{
        //    //No option to create a blank store.  Generate a self signed cert with some default and limited validity.
        //    string keyToolCommand = $"{KeytoolPath}keytool -genkeypair -keystore {storePath} -storepass {storePassword} -dname \"cn=New Certificate Store\" -validity 1 -alias \"NewCertStore\"";
        //    SSH.RunCommand(keyToolCommand, null, ServerType == ServerTypeEnum.Linux && ApplicationSettings.UseSudo, StorePassword == null ? null : new string[] { StorePassword });
        //}

        //internal void AddCertificateToStore(string alias, byte[] certBytes, bool overwrite)
        //{
        //    string keyToolCommand = $"{KeytoolPath}keytool -import -alias '{alias}' -keystore '{StorePath + StoreFileName}' -file '{UploadFilePath}{FILE_NAME_REPL}.pem' -deststorepass '{StorePassword}' -noprompt";
        //    AddEntry(keyToolCommand, alias, certBytes, null, overwrite);
        //}

        //internal void AddPFXCertificateToStore(string sourceAlias, string destAlias, byte[] certBytes, string pfxPassword, string entryPassword, bool overwrite)
        //{
        //    string keyToolCommand = $"{KeytoolPath}keytool -importkeystore -srckeystore '{UploadFilePath}{FILE_NAME_REPL}.p12' -srcstoretype PKCS12 -srcstorepass '{pfxPassword}' -srcalias '{sourceAlias}' " +
        //        $"-destkeystore '{StorePath + StoreFileName}' -destalias '{destAlias}' -deststoretype JKS -destkeypass '{(string.IsNullOrEmpty(entryPassword) ? StorePassword : entryPassword)}' -deststorepass '{StorePassword}' -noprompt";
        //    AddEntry(keyToolCommand, destAlias, certBytes, pfxPassword, overwrite);
        //}

        //private bool IsJavaInstalled()
        //{
        //    string keyToolCommand = ServerType == ServerTypeEnum.Linux ? $"which java" : "java -version 2>&1";
        //    string result = SSH.RunCommand(keyToolCommand, null, ServerType == ServerTypeEnum.Linux && ApplicationSettings.UseSudo, null);
        //    return !(string.IsNullOrEmpty(result));
        //}

        //private void AddEntry(string command, string alias, byte[] certBytes, string pfxPassword, bool overwrite)
        //{
        //    string fileSuffix = string.IsNullOrEmpty(pfxPassword) ? ".pem" : ".p12";
        //    string fileName = Guid.NewGuid().ToString().Replace("-", string.Empty);
        //    command = command.Replace(FILE_NAME_REPL, fileName);

        //    try
        //    {
        //        if (DoesCertificateAliasExist(alias))
        //        {
        //            if (overwrite)
        //                DeleteCertificateByAlias(alias);
        //            else
        //                throw new PKCS12Exception($"Alias already exists in certificate store.");
        //        }

        //        SSH.UploadCertificateFile(UploadFilePath, $"{fileName}{fileSuffix}", certBytes);

        //        mutex.WaitOne();
        //        SSH.RunCommand(command, null, ServerType == ServerTypeEnum.Linux && ApplicationSettings.UseSudo, StorePassword == null ? null : new string[] { StorePassword });
        //    }
        //    catch (Exception ex)
        //    {
        //        throw new PKCS12Exception($"Error attempting to add certficate for store path={StorePath}, file name={StoreFileName}.", ex);
        //    }
        //    finally
        //    {
        //        try
        //        {
        //            SSH.RemoveCertificateFile(StorePath, $"{fileName}{fileSuffix}");
        //        }
        //        catch (Exception) { }
        //        finally
        //        {
        //            mutex.ReleaseMutex();
        //        }
        //    }
        //}

        private void SplitStorePathFile(string pathFileName)
        {
            try
            {
                string workingPathFileName = pathFileName.Replace(@"\", @"/");
                int separatorIndex = workingPathFileName.LastIndexOf(@"/");
                StoreFileName = pathFileName.Substring(separatorIndex + 1);
                StorePath = pathFileName.Substring(0, separatorIndex + 1);
            }
            catch (Exception ex)
            {
                throw new PKCS12Exception($"Error attempting to parse certficate store path={StorePath}, file name={StoreFileName}.", ex);
            }
        }

        private int GetChainLength(string certificates)
        {
            int count = 0;
            int i = 0;
            while ((i = certificates.IndexOf(BEG_DELIM, i)) != -1)
            {
                i += BEG_DELIM.Length;
                count++;
            }
            return count;
        }

        private string FormatStorePassword()
        {
            return (!string.IsNullOrEmpty(StorePassword) ? $"-storepass '{StorePassword}'" : string.Empty);
        }

        private string FormatPath(string path)
        {
            return path + (path.Substring(path.Length - 1) == @"\" ? string.Empty : @"\");
        }
    }

    class PKCS12Exception : ApplicationException
    {
        public PKCS12Exception(string message) : base(message)
        { }

        public PKCS12Exception(string message, Exception ex) : base(message, ex)
        { }
    }
}