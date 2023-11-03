function Invoke-ProcessAsImpersonatedUser {
    <#
    .SYNOPSIS
        Launches a process through impersonating the logged in user.
        Used to launch processes in user context from system with the ability to hide the console completely.
    .PARAMETER Process
        The process to launch. Can be a path to an executable or a command.
    .PARAMETER Arguments
        Arguments to pass to the process.
    .PARAMETER Visible
        Switch to make the process visible.
        Invisibility is only supported by certain processes, such as cmd.exe, powershell.exe and pwsh.exe.
    .PARAMETER SessionID
        The session ID to launch the process in.
        Defaults to the session ID of the current process.
    .EXAMPLE Running a visible process as user (check whoami)
        Invoke-ProcessAsImpersonatedUser -Process cmd.exe -Visible
    .EXAMPLE Running an invisible process as user with arguments
        $Args = @{
            Process = "powershell.exe"
            Arguments = "-NoProfile -NoLogo -ExecutionPolicy Bypass -Command Get-Process"
        }
        Invoke-ProcessAsImpersonatedUser @Args
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
        [int32]$SessionID = (Get-Process -Id $PID).SessionId
    )

    $LogSource = "Invoke-ProcessAsImpersonatedUser"

    try {
        # If the current scope isn't SYSTEM context, return as function will not work
        if (-not ($env:USERNAME -eq "$env:COMPUTERNAME$")) {
            Write-Warning -Message "Function requires SYSTEM privileges."
            return $false
        }

        # Paths require double backslashes to work in the inline code
        $Process = $Process.Replace("\", "\\")
        $Arguments = $Arguments.Replace("\", "\\")

        # Should the process be visible?
        $Visibility = switch ($Visible) {
            $true  { 1 }
            $false { 0 }
        }

        # Add ProcessLauncher class and methods to impersonate as user and launch processes
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

    public PROCESS_INFORMATION LaunchProcess(string Process, string Arguments, int Visibility, uint sessionId) {
        IntPtr hToken;
        if (!WTSQueryUserToken(sessionId, out hToken)) {
            throw new System.ComponentModel.Win32Exception();
        }

        IntPtr hNewToken;
        if (!DuplicateTokenEx(hToken, 0x10000000, IntPtr.Zero, 2, 1, out hNewToken)) {
            throw new System.ComponentModel.Win32Exception();
        }

        STARTUPINFO si = new STARTUPINFO();
        si.cb = Marshal.SizeOf(si);
        si.lpDesktop = "Winsta0\\Default";
        si.dwFlags = 1; // STARTF_USESHOWWINDOW
        si.wShowWindow = (short)Visibility; // SW_HIDE
        PROCESS_INFORMATION pi;

        string command = String.Format("{0} {1}", Process, Arguments);
        
        if (!CreateProcessWithTokenW(hNewToken, 1, null, command, 0, IntPtr.Zero, null, ref si, out pi)) {
            throw new System.ComponentModel.Win32Exception();
        }

        return pi;
    }
}
"@ -ErrorAction Stop
        $launcher = New-Object ProcessLauncher -ErrorAction Stop
        $Result = $launcher.LaunchProcess($Process, $Arguments, $Visibility, $SessionID)

        # Return the process ID and handle of the launched process, maybe follow up to make sure it's closed?
        return $Result
    }
    catch {
        $LogMessage = "$LogSource threw an exception: $PSItem"
        Write-Warning -Message $LogMessage
        
        return $false
    }
}