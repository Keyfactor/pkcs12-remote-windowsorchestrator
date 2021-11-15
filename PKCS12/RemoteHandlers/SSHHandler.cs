// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

using Renci.SshNet;

namespace Keyfactor.Extensions.Orchestrator.PKCS12.RemoteHandlers
{
    class SSHHandler : BaseRemoteHandler
    {
        private ConnectionInfo Connection { get; set; }

        private SshClient sshClient;

        internal SSHHandler(string server, string serverLogin, string serverPassword)
        {
            Server = server;

            List<AuthenticationMethod> authenticationMethods = new List<AuthenticationMethod>();
            if (serverPassword.Length < PASSWORD_LENGTH_MAX)
                authenticationMethods.Add(new PasswordAuthenticationMethod(serverLogin, serverPassword));
            else
                authenticationMethods.Add(new PrivateKeyAuthenticationMethod(serverLogin, new PrivateKeyFile[] { new PrivateKeyFile(new MemoryStream(Encoding.ASCII.GetBytes(ReplaceSpacesWithLF(serverPassword)))) }));

            Connection = new ConnectionInfo(server, serverLogin, authenticationMethods.ToArray());
        }

        public override void Initialize()
        {
            sshClient = new SshClient(Connection);
            sshClient.Connect();
        }

        public override void Terminate()
        {
            sshClient.Disconnect();
            sshClient.Dispose();
        }

        public override string RunCommand(string commandText, object[] arguments, bool withSudo, string[] passwordsToMaskInLog)
        {
            Logger.Debug($"RunCommand: {Server}");

            string sudo = $"sudo -i -S ";
            string echo = $"echo -e '\n' | ";

            try
            {
                if (withSudo)
                    commandText = sudo + commandText;

                commandText = echo + commandText;

                string displayCommand = commandText;
                if (passwordsToMaskInLog != null)
                {
                    foreach (string password in passwordsToMaskInLog)
                        displayCommand = displayCommand.Replace(password, PASSWORD_MASK_VALUE);
                }

                using (SshCommand command = sshClient.CreateCommand($"{commandText}"))
                {
                    Logger.Debug($"RunCommand: {displayCommand}");
                    command.Execute();
                    Logger.Debug($"SSH Results: {displayCommand}::: {command.Result}::: {command.Error}");

                    if (command.Result.ToLower().Contains(KEYTOOL_ERROR))
                        throw new ApplicationException(command.Result);

                    return command.Result;
                }
            }
            catch (Exception ex)
            {
                Logger.Debug($"Exception during RunCommand...{ExceptionHandler.FlattenExceptionMessages(ex, ex.Message)}");
                throw ex;
            }
        }

        public override void UploadCertificateFile(string path, string fileName, byte[] certBytes)
        {
            Logger.Debug($"UploadCertificateFile: {path} {fileName}");

            try
            {
                using (SftpClient client = new SftpClient(Connection))
                {
                    try
                    {
                        client.Connect();
                        client.ChangeDirectory(FormatFTPPath(path));

                        using (MemoryStream stream = new MemoryStream(certBytes))
                        {
                            client.UploadFile(stream, fileName);
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.Debug("Exception during upload...");
                        Logger.Debug($"Upload Exception: {ExceptionHandler.FlattenExceptionMessages(ex, ex.Message)}");
                        throw ex;
                    }
                    finally
                    {
                        client.Disconnect();
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Debug($"Exception making SFTP connection - {ex.Message}");
                throw ex;
            }
        }

        public override byte[] DownloadCertificateFile(string path)
        {
            Logger.Debug($"DownloadCertificateFile: {path}");

            string downloadPath = path;
            string altPathOnly = string.Empty;
            string altFileNameOnly = string.Empty;

            if (ApplicationSettings.UseSeparateUploadFilePath)
            {
                SplitStorePathFile(path, out altPathOnly, out altFileNameOnly);
                downloadPath = ApplicationSettings.SeparateUploadFilePath + altFileNameOnly;
            }

            using (SftpClient client = new SftpClient(Connection))
            {
                try
                {
                    client.Connect();

                    if (ApplicationSettings.UseSeparateUploadFilePath)
                        RunCommand($"cp {path} {downloadPath}", null, ApplicationSettings.UseSudo, null);

                    using (MemoryStream stream = new MemoryStream())
                    {
                        client.DownloadFile(FormatFTPPath(downloadPath), stream);
                        if (ApplicationSettings.UseSeparateUploadFilePath)
                            RunCommand($"rm {downloadPath}", null, ApplicationSettings.UseSudo, null);
                        return stream.ToArray();
                    }
                }
                finally
                {
                    client.Disconnect();
                }
            }
        }

        public override void RemoveCertificateFile(string path, string fileName)
        {
            Logger.Debug($"RemoveCertificateFile: {path} {fileName}");

            RunCommand($"rm {path}{fileName}", null, ApplicationSettings.UseSudo, null);
        }

        private void SplitStorePathFile(string pathFileName, out string path, out string fileName)
        {
            try
            {
                int separatorIndex = pathFileName.LastIndexOf(pathFileName.Substring(0, 1) == "/" ? @"/" : @"\");
                fileName = pathFileName.Substring(separatorIndex + 1);
                path = pathFileName.Substring(0, separatorIndex + 1);
            }
            catch (Exception ex)
            {
                throw new PKCS12Exception($"Error attempting to parse certficate store/key path={pathFileName}.", ex);
            }
        }

        private string ReplaceSpacesWithLF(string privateKey)
        {
            return privateKey.Replace(" RSA PRIVATE ", "^^^").Replace(" ", System.Environment.NewLine).Replace("^^^", " RSA PRIVATE ");
        }

        private string FormatFTPPath(string path)
        {
            return path.Substring(0, 1) == @"/" ? path : @"/" + path.Replace("\\", "/");
        }
    }
}
