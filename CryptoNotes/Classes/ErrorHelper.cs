using System;
using System.Collections.Generic;
using System.Text;

namespace CryptoNotes.Classes
{
    static public class ErrorHelper
    {
        static public string FormatError(Exception e)
        {
            System.Diagnostics.StackTrace trace = new System.Diagnostics.StackTrace(e, true);

            string errblock;
            errblock = "------------------------------------------\n";
            errblock += "Type:\t" + e.GetType().ToString() + "\n";
            errblock += "Line:\t" + trace.GetFrame(0).GetFileLineNumber();
            errblock += "\tColumn:\t" + trace.GetFrame(0).GetFileColumnNumber() + "\n";
            errblock += "Method:\t" + trace.GetFrame(0).GetMethod().Name + "\n";
            errblock += "Message:\t" + e.Message + "\n";
            errblock += "HelpLink:\t" + e.HelpLink + "\n";
            if (e.Data != null || e.Data.Count > 0)
            {
                errblock += "\n[Start Data Dictionary]\n";
                foreach (KeyValuePair<object,object> kp in e.Data)
                {
                    errblock += "\tKey:\t" + kp.Key.ToString() + "\n";
                    errblock += "\tValue:\t" + kp.Value.ToString() + "\n";
                }
                errblock += "\n[End Data Dictionary]\n";
            }
            errblock += "StackTrace:\n" + e.StackTrace + "\n";
            errblock += "------------------------------------------\n";
            return errblock;
        }
    }
}
