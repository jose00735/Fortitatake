; FortiTatake Windows installer (NSIS 3).
; Per-user install: no administrator rights needed. Build with tools/build_windows.sh.
Unicode true
ManifestDPIAware true
RequestExecutionLevel user
SetCompressor /SOLID lzma

!ifndef VERSION
  !define VERSION "0.0.0"
!endif
!ifndef DIST
  !define DIST "..\dist"
!endif
!define APP "FortiTatake"
!define EXE "fortitatake.exe"
!define UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP}"

Name "${APP} ${VERSION}"
OutFile "${DIST}\FortiTatake-Setup-v${VERSION}.exe"
InstallDir "$LOCALAPPDATA\Programs\${APP}"
InstallDirRegKey HKCU "${UNINST_KEY}" "InstallLocation"
BrandingText "${APP} ${VERSION}"
VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName" "${APP}"
VIAddVersionKey "FileDescription" "${APP} installer"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "LegalCopyright" "jose00735"

!include "MUI2.nsh"
!define MUI_ICON "..\assets\fortitatake.ico"
!define MUI_UNICON "..\assets\fortitatake.ico"
!define MUI_ABORTWARNING
!define MUI_WELCOMEPAGE_TITLE "Install ${APP} ${VERSION}"
!define MUI_WELCOMEPAGE_TEXT "${APP} is your study app for Fortinet professional services interviews and certifications.$\r$\n$\r$\nIt installs for your Windows user only and needs no administrator rights. Your study progress is kept in %APPDATA%\${APP} and survives updates.$\r$\n$\r$\nIf ${APP} is open, it will be closed during the installation."
!define MUI_FINISHPAGE_RUN "$INSTDIR\${EXE}"
!define MUI_FINISHPAGE_RUN_TEXT "Open ${APP} now"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Function CloseApp
  nsExec::Exec 'taskkill /IM ${EXE} /F'
  Pop $0
  Sleep 500
FunctionEnd

Function un.CloseApp
  nsExec::Exec 'taskkill /IM ${EXE} /F'
  Pop $0
  Sleep 500
FunctionEnd

Section "${APP} (required)" SecApp
  SectionIn RO
  Call CloseApp
  SetOutPath "$INSTDIR"
  File "${DIST}\${EXE}"
  File "/oname=README.md" "..\README.md"
  File "/oname=${APP}.ico" "..\assets\fortitatake.ico"
  ; QEMU runner for FortiTatake OS (stripped: x86_64, WHPX + TCG, no graphics)
  RMDir /r "$INSTDIR\qemu"
  SetOutPath "$INSTDIR\qemu"
  File /r "${DIST}\qemu-win\*"
  SetOutPath "$INSTDIR"
  WriteUninstaller "$INSTDIR\Uninstall ${APP}.exe"

  CreateDirectory "$SMPROGRAMS\${APP}"
  CreateShortcut "$SMPROGRAMS\${APP}\${APP}.lnk" "$INSTDIR\${EXE}" "" "$INSTDIR\${EXE}" 0
  CreateShortcut "$SMPROGRAMS\${APP}\Uninstall ${APP}.lnk" "$INSTDIR\Uninstall ${APP}.exe"

  WriteRegStr HKCU "${UNINST_KEY}" "DisplayName" "${APP}"
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKCU "${UNINST_KEY}" "Publisher" "jose00735"
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayIcon" "$INSTDIR\${EXE},0"
  WriteRegStr HKCU "${UNINST_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "${UNINST_KEY}" "UninstallString" '"$INSTDIR\Uninstall ${APP}.exe"'
  WriteRegStr HKCU "${UNINST_KEY}" "QuietUninstallString" '"$INSTDIR\Uninstall ${APP}.exe" /S'
  WriteRegDWORD HKCU "${UNINST_KEY}" "NoModify" 1
  WriteRegDWORD HKCU "${UNINST_KEY}" "NoRepair" 1
  WriteRegDWORD HKCU "${UNINST_KEY}" "EstimatedSize" 16000
SectionEnd

Section "Desktop shortcut" SecDesktop
  CreateShortcut "$DESKTOP\${APP}.lnk" "$INSTDIR\${EXE}" "" "$INSTDIR\${EXE}" 0
SectionEnd

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecApp} "The ${APP} app and Start menu shortcuts."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecDesktop} "A shortcut on your desktop."
!insertmacro MUI_FUNCTION_DESCRIPTION_END

Section "Uninstall"
  Call un.CloseApp
  Delete "$INSTDIR\${EXE}"
  Delete "$INSTDIR\README.md"
  Delete "$INSTDIR\${APP}.ico"
  Delete "$INSTDIR\Uninstall ${APP}.exe"
  RMDir /r "$INSTDIR\qemu"
  RMDir "$INSTDIR"
  Delete "$SMPROGRAMS\${APP}\${APP}.lnk"
  Delete "$SMPROGRAMS\${APP}\Uninstall ${APP}.lnk"
  RMDir "$SMPROGRAMS\${APP}"
  Delete "$DESKTOP\${APP}.lnk"
  DeleteRegKey HKCU "${UNINST_KEY}"
  ; Study progress is kept unless the user explicitly asks to delete it (never in silent mode).
  IfSilent done
  MessageBox MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2 "Also delete your study progress and sync settings?$\r$\n($APPDATA\${APP})$\r$\n$\r$\nChoose No to keep them for a future install." IDNO done
  RMDir /r "$APPDATA\${APP}"
  done:
SectionEnd
