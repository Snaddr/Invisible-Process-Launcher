function Invoke-CustomProcess {
    <#
    .SYNOPSIS
        Launches a new process using a custom inline C# class.
    .PARAMETER Process
        The process to launch. Can be a path to an executable or a command.
    .PARAMETER Arguments
        Arguments to pass to the process.
    .PARAMETER Visible
        Switch to make the process visible.
        Invisibility is only supported by certain processes, such as cmd.exe, powershell.exe and pwsh.exe.
    .PARAMETER Impersonate
        Switch to activate impersonation of currently logged in user when running in system context.
    .PARAMETER SessionID
        The session ID to impersonate if impersonation is enabled.
        Defaults to the session ID of the current PID (logged in user).
    .EXAMPLE
        Invoke-CustomProcess -Process cmd.exe -Visible -Impersonate
    .EXAMPLE
        $Args = @{
            Process = "powershell.exe"
            Arguments = "-NoProfile -NoLogo -ExecutionPolicy Bypass -Command Get-Process"
        }
        Invoke-CustomProcess @Args
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$Process,
        [Parameter(Mandatory=$false)]
        [String]$Arguments,
        [Parameter(Mandatory=$false)]
        [Switch]$Visible = $false,
        [Parameter(Mandatory=$false)]
        [Switch]$Impersonate = $false,
        [Parameter(Mandatory=$false)]
        [int32]$SessionID = (Get-Process -Id $PID).SessionId
    )

    $LogSource = "Invoke-CustomProcess"

    try {
        if ($Impersonate) {
            # If the current scope isn't SYSTEM context when impersonating, return as function will not work
            if (-not ($env:USERNAME -eq "$env:COMPUTERNAME$")) {
                Write-Warning -Message "SYSTEM privileges are required to impersonate a user."
                return $false
            }
        }

        # Paths require double backslashes to work
        $Process = $Process.Replace("\", "\\")
        $Arguments = $Arguments.Replace("\", "\\")

        # Should the process be visible?
        $Visibility = switch ($Visible) {
            $true  { 1 }
            $false { 0 }
        }

        # Add custom inline class to launch process, parameters are passed to the class when calling the method
        Add-Type -TypeDefinition @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

public class ProcessLauncher {
    [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, 
        IntPtr lpTokenAttributes, int ImpersonationLevel, int TokenType, out IntPtr phNewToken);

    [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern bool CreateProcessWithTokenW(IntPtr hToken, int dwLogonFlags, 
        string lpApplicationName, string lpCommandLine, int dwCreationFlags, IntPtr lpEnvironment, 
        string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInfo);

    [DllImport("Wtsapi32.dll")]
    public static extern bool WTSQueryUserToken(uint sessionId, out IntPtr Token);

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO {
        public Int32 cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public Int32 dwX;
        public Int32 dwY;
        public Int32 dwXSize;
        public Int32 dwYSize;
        public Int32 dwXCountChars;
        public Int32 dwYCountChars;
        public Int32 dwFillAttribute;
        public Int32 dwFlags;
        public Int16 wShowWindow;
        public Int16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    public PROCESS_INFORMATION LaunchProcess(string Process, string Arguments, int Visibility, uint sessionId, bool Impersonate) {
        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
    
        if (Impersonate) {
            IntPtr hToken;
            IntPtr hNewToken;

            if (!WTSQueryUserToken(sessionId, out hToken)) {
                throw new System.ComponentModel.Win32Exception();
            }

            if (!DuplicateTokenEx(hToken, 0x10000000, IntPtr.Zero, 2, 1, out hNewToken)) {
                throw new System.ComponentModel.Win32Exception();
            }

            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            si.lpDesktop = "Winsta0\\Default";
            si.dwFlags = 1; // STARTF_USESHOWWINDOW
            si.wShowWindow = (short)Visibility; // SW_HIDE

            string command = String.Format("{0} {1}", Process, Arguments);

            if (!CreateProcessWithTokenW(hNewToken, 1, null, command, 0, IntPtr.Zero, null, ref si, out pi)) {
                throw new System.ComponentModel.Win32Exception();
            }
        }
        else {
            var startInfo = new ProcessStartInfo(Process, Arguments)
            {
                UseShellExecute = false,
                CreateNoWindow = Visibility == 0
            };

            using (var proc = new Process { StartInfo = startInfo })
            {
                proc.Start();
                pi.dwProcessId = proc.Id;
                pi.dwThreadId = proc.Threads[0].Id;
            }
        }

        return pi;
    }
}
"@ -ErrorAction Stop
        $launcher = New-Object ProcessLauncher -ErrorAction Stop
        $Result = $launcher.LaunchProcess($Process, $Arguments, $Visibility, $SessionID, $Impersonate)
        return $Result
    }
    catch {
        $LogMessage = "$LogSource threw an exception: $PSItem"
        Write-Warning $LogMessage
        $PSItem | Format-List -Force
        
        return $false
    }
}