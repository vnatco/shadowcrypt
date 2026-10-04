; ShadowCrypt NSIS installer hooks (included by the Tauri NSIS template).
;
; - Removes ShadowCrypt 1.x (Electron) before installing, so its files are not
;   left mixed into the new install and its registry entries don't override ours.
; - Adds "Open With ShadowCrypt" to the right-click menu of every file.
; - Rewrites the .aes open command with a quoted path (Tauri writes it unquoted).
;
; All registry writes use SHCTX, which the template points at HKLM for
; "All Users" installs and at HKCU for "Just Me" installs.

; electron-builder registered ShadowCrypt 1.x under this key (derived from its appId).
!define SC1_UNINSTKEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\0f6642c6-ec85-5129-991f-f02620378855"

; Uninstall ShadowCrypt 1.x if registered under ROOT (HKLM or HKCU).
!macro SC_REMOVE_V1 ROOT
  ReadRegStr $R0 ${ROOT} "${SC1_UNINSTKEY}" "UninstallString"
  ${If} $R0 != ""
    MessageBox MB_OKCANCEL|MB_ICONINFORMATION "ShadowCrypt 1.x is installed and will be removed first.$\r$\n$\r$\nYour encrypted files are not affected." /SD IDOK IDOK +3
      SetErrorLevel 1
      Quit

    ; UninstallString looks like: "C:\...\Uninstall ShadowCrypt.exe" /allusers
    ; Split it into the executable path ($R3) and its arguments ($R5).
    StrCpy $R3 $R0
    StrCpy $R5 ""
    StrCpy $R1 $R0 1
    ${If} $R1 == '"'
      StrCpy $R2 1
      ${Do}
        StrCpy $R1 $R0 1 $R2
        ${If} $R1 == '"'
        ${OrIf} $R1 == ""
          ${ExitDo}
        ${EndIf}
        IntOp $R2 $R2 + 1
      ${Loop}
      IntOp $R4 $R2 - 1
      StrCpy $R3 $R0 $R4 1
      IntOp $R2 $R2 + 1
      StrCpy $R5 $R0 "" $R2
    ${EndIf}
    ${GetParent} $R3 $R6

    ${If} ${FileExists} $R3
      ; _?= makes the uninstaller run in place so we can wait for it to finish.
      ${If} ${ROOT} == HKLM
        ; Needs admin rights; elevates (UAC) if this installer isn't elevated.
        ExecShellWait "runas" "$R3" "$R5 /S _?=$R6"
      ${Else}
        ExecWait '"$R3" $R5 /S _?=$R6'
      ${EndIf}
      ; Run in place, the uninstaller can't delete itself or its folder.
      Delete "$R3"
      RMDir "$R6"
    ${EndIf}

    ; Never install over a 1.x install that is still present.
    ReadRegStr $R0 ${ROOT} "${SC1_UNINSTKEY}" "UninstallString"
    ${If} $R0 != ""
      MessageBox MB_OK|MB_ICONSTOP "ShadowCrypt 1.x could not be removed.$\r$\n$\r$\nPlease uninstall it from Settings > Apps, then run this installer again." /SD IDOK
      SetErrorLevel 2
      Quit
    ${EndIf}
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREINSTALL
  !insertmacro SC_REMOVE_V1 HKLM
  !insertmacro SC_REMOVE_V1 HKCU

  ; ShadowCrypt 1.x always wrote its file association to HKCU and its own
  ; uninstaller does not reliably remove it. A per-user .aes mapping overrides
  ; the all-users one, so drop anything that still points at the 1.x handler.
  ReadRegStr $R0 HKCU "Software\Classes\.aes" ""
  ${If} $R0 == "ShadowCrypt.aes"
    DeleteRegValue HKCU "Software\Classes\.aes" ""
    DeleteRegValue HKCU "Software\Classes\.aes" "PerceivedType"
    DeleteRegKey /ifempty HKCU "Software\Classes\.aes"
  ${EndIf}
  DeleteRegKey HKCU "Software\Classes\ShadowCrypt.aes"
!macroend

!macro NSIS_HOOK_POSTINSTALL
  WriteRegStr SHCTX "Software\Classes\*\shell\ShadowCrypt"         ""     "Open With ShadowCrypt"
  WriteRegStr SHCTX "Software\Classes\*\shell\ShadowCrypt"         "Icon" "$INSTDIR\ShadowCrypt.exe,0"
  WriteRegStr SHCTX "Software\Classes\*\shell\ShadowCrypt\command" ""     '"$INSTDIR\ShadowCrypt.exe" "%1"'
  WriteRegStr SHCTX "Software\Classes\ShadowCrypt Encrypted File\shell\open\command" "" '"$INSTDIR\ShadowCrypt.exe" "%1"'
  ; Refresh Explorer so the menu entry and icons appear immediately
  System::Call 'shell32::SHChangeNotify(i 0x08000000, i 0, p 0, p 0)'
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  DeleteRegKey SHCTX "Software\Classes\*\shell\ShadowCrypt"
  ${If} $UpdateMode <> 1
    ; Tauri "restores" the previous .aes association on uninstall, which leaves
    ; an .aes key with an empty default value when there was none before. An
    ; empty per-user key would also hide an all-users install's association,
    ; so remove it when nothing else claims .aes.
    ReadRegStr $R0 SHCTX "Software\Classes\.aes" ""
    ${If} $R0 == ""
      DeleteRegValue SHCTX "Software\Classes\.aes" "ShadowCrypt Encrypted File_backup"
      DeleteRegValue SHCTX "Software\Classes\.aes" ""
      DeleteRegKey /ifempty SHCTX "Software\Classes\.aes"
    ${EndIf}
    ; Install-location record the template only removes when "delete app data" is ticked
    DeleteRegKey SHCTX "Software\ShadowCrypt\ShadowCrypt"
    DeleteRegKey /ifempty SHCTX "Software\ShadowCrypt"
  ${EndIf}
  ; The app keeps no user data; this folder only holds the WebView2 cache of
  ; the user running the uninstaller. Keep it during updates.
  ${If} $UpdateMode <> 1
    SetShellVarContext current
    RMDir /r "$LOCALAPPDATA\dev.vnat.shadowcrypt"
  ${EndIf}
  System::Call 'shell32::SHChangeNotify(i 0x08000000, i 0, p 0, p 0)'
!macroend
