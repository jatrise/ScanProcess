using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Configuration;
using System.Data;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Timers;
using VirusTotalNET;
using VirusTotalNET.ResponseCodes;
using VirusTotalNET.Results;

namespace ScanProcess
{
    public partial class ScanService : ServiceBase
    {
        private System.Timers.Timer timer1 = null;
        private EventLog eventLog1;
        BackgroundWorker workerThread = null;
        bool _keepRunning = false;
        string folderPathQuarantine = Environment.GetFolderPath(Environment.SpecialFolder.MyPictures) + "\\UploadedFiles\\";
        string destinationFolder = Environment.GetFolderPath(Environment.SpecialFolder.MyPictures) + "\\DestinationFiles\\";

        public ScanService()
        {
            InitializeComponent();
            this.ServiceName = "ScanService";
            this.CanStop = true;
            this.CanPauseAndContinue = true;
            this.AutoLog = true;
           // CreateAutoLog();
        }

        public void onDebug()
        {
            OnStart(null);
        }

        protected override void OnStart(string[] args)
        {
            //eventLog1.WriteEntry("OnStart...");
            
            //Set the process to run (every 3 min) 
            SetProcessTimer();

            //InstantiateBackgroundThread();
        }

        private void WorkerThread_DoWork(object sender, DoWorkEventArgs e)
        {
            DateTime startTime = DateTime.Now;

            _keepRunning = true;

            while (_keepRunning)
            {
                Thread.Sleep(1000);

                string timeElapsedInstring = (DateTime.Now - startTime).ToString(@"hh\:mm\:ss");

                workerThread.ReportProgress(0, timeElapsedInstring);

                if (workerThread.CancellationPending)
                {
                    // this is important as it set the cancelled property of RunWorkerCompletedEventArgs to true
                    e.Cancel = true;
                    break;
                }
            }
        }


        protected override void OnStop()
        {
        }

        private void StartProcess()
        {
            if (Directory.Exists(folderPathQuarantine))
            {
                ProcessDirectory(folderPathQuarantine);
            }
            else
            {
                //eventLog1.WriteEntry("Folder path not found..."  + folderPathQuarantine);
            }
        }

        private void SetProcessTimer()
        {
            timer1 = new System.Timers.Timer();
            this.timer1.Interval = 240000; //every 4 min
            this.timer1.Elapsed += new System.Timers.ElapsedEventHandler(this.timer1_Tick);
            timer1.Enabled = true;
        }

        private void CreateAutoLog()
        {
            eventLog1 = new EventLog();

            // Turn off autologging
            this.AutoLog = false;

            // create an event source, specifying the name of a log that
            // does not currently exist to create a new, custom log
            if (!System.Diagnostics.EventLog.SourceExists(nameof(ScanService)))
            {
                System.Diagnostics.EventLog.CreateEventSource(
                    nameof(ScanService), "ScanServiceLog");
            }
            // configure the event log instance to use this source name
            eventLog1.Source = nameof(ScanService);
            eventLog1.Log = "ScanServiceLog";
        }

        private void ProcessDirectory(string targetDirectory)
        {
            // Process the list of files found in the directory.
            string[] fileEntries = Directory.GetFiles(targetDirectory);

            Parallel.ForEach(fileEntries,async file => await ProcessFile(file));
            //foreach (string fileName in fileEntries)
            //{
            //    //Run async process for each file
            //    ProcessFile(fileName);
            //}

            // Recurse into subdirectories of this directory.
            //string[] subdirectoryEntries = Directory.GetDirectories(targetDirectory);
            //foreach (string subdirectory in subdirectoryEntries)
            //    ProcessDirectory(subdirectory);
        }

        // Insert logic for processing found files here.
        private async Task ProcessFile(string fileName)
        {
            try
            {
                //var virusTotalKey = ConfigurationManager.AppSettings["VirusTotalKey"];

                var virusTotalKey = Properties.Settings.Default.VirusTotalKey;
                VirusTotal virusTotal = new VirusTotal(virusTotalKey);

                virusTotal.UseTLS = true;
                var fileByteArray = GetFileData(fileName);
                FileReport fileReport = await virusTotal.GetFileReportAsync(fileByteArray);

                bool hasFileBeenScannedBefore = fileReport?.ResponseCode == FileReportResponseCode.Present;

                if (hasFileBeenScannedBefore && fileReport?.ResponseCode == FileReportResponseCode.Present)
                {
                    switch (fileReport.Positives)
                    {
                        case 0:
                            MoveFile(fileName);
                            break;
                        default:
                            //eventLog1.WriteEntry("File was detected with a virus" + fileName);
                            break;
                    }
                }
                else
                {
                    //eventLog1.WriteEntry("This file has not been submited for scanning yet..." + fileName);
                }
            }
            catch (Exception ex)
            {

            }
            Console.WriteLine("Processed file '{0}'.", fileName);
        }

        private byte[] GetFileData(string fileName)
        {
            byte[] fileByteArray = new byte[fileName.Length];
            fileByteArray= File.ReadAllBytes(fileName);
            return fileByteArray;
        }

        private void MoveFile(string fileName)
        {
            ;

            try
            {
                if (!Directory.Exists(destinationFolder))
                    Directory.CreateDirectory(destinationFolder);

                File.Move(fileName, destinationFolder + GetFileName(fileName));
            }
            catch (Exception e)
            {
                //eventLog1.WriteEntry("Error moving the file: " + fileName);
            }

        }

        private string GetFileName(string postedFile)
        {
            string fileName;

            var lastIndex = postedFile.LastIndexOf('\\');

            fileName = postedFile.Remove(0, lastIndex + 1);

            return fileName;
        }

        // Timer1_tick will Start process every hour
        private void timer1_Tick(object sender, ElapsedEventArgs e)
        {
            //Write code here to do some job depends on your requirement
            StartProcess();
        }
    }
}
