; ShadowCrypt NSIS installer hooks (included by the Tauri NSIS template).
; The .aes file association itself is registered by Tauri from tauri.conf.json;
; these hooks add "Open With ShadowCrypt" to the right-click menu of every file.

!macro NSIS_HOOK_POSTINSTALL
  WriteRegStr HKCU "Software\Classes\*\shell\ShadowCrypt"         ""     "Open With ShadowCrypt"
  WriteRegStr HKCU "Software\Classes\*\shell\ShadowCrypt"         "Icon" "$INSTDIR\ShadowCrypt.exe,0"
  WriteRegStr HKCU "Software\Classes\*\shell\ShadowCrypt\command" ""     '"$INSTDIR\ShadowCrypt.exe" "%1"'
  ; Tauri writes the .aes open command with an unquoted executable path, which
  ; breaks when the install path contains spaces. Rewrite it quoted.
  WriteRegStr HKCU "Software\Classes\ShadowCrypt Encrypted File\shell\open\command" "" '"$INSTDIR\ShadowCrypt.exe" "%1"'
  ; Refresh Explorer so the menu entry and icons appear immediately
  System::Call 'shell32::SHChangeNotify(i 0x08000000, i 0, p 0, p 0)'
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  DeleteRegKey HKCU "Software\Classes\*\shell\ShadowCrypt"
  ; The app keeps no user data; this folder only holds the WebView2 cache.
  RMDir /r "$LOCALAPPDATA\dev.vnat.shadowcrypt"
  System::Call 'shell32::SHChangeNotify(i 0x08000000, i 0, p 0, p 0)'
!macroend
