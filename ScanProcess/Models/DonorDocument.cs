using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ScanProcess.Models
{
   public class DonorFiles
    {
        public string FileName { get; set; }

        public string CreatedBy { get; set; }

        public string DonationId { get; set; }

        public string DonorId { get; set; }

        public byte[] FileData { get; set; }

        public DateTime CreatedDate { get; set; }
    }

    public class Donor
    {
        public string DonorId { get; set; }

        public string DonationId { get; set; }

    }
}
