===============================================================================
  SELENNE - endpoint collector for Windows
  Account: __OWNER__          Dashboard: https://__MANAGER__
===============================================================================

WHAT IS IN THIS PACKAGE
-----------------------
  install-selenne-agent.cmd   The installer. Double-click it.
  selenne.ico                 Selenne logo, installed alongside the collector
                              and used for the Start Menu entry.
  selenne-logo.png            The same mark at 512x512, for your own use.
  README.txt                  This file.

INSTALL
-------
  1. Unzip this folder somewhere (Desktop or Downloads is fine). Keep
     install-selenne-agent.cmd and selenne.ico together - the installer looks
     for the icon next to itself.
  2. Double-click install-selenne-agent.cmd.
  3. Windows asks for administrator rights (the standard UAC prompt) - approve
     it. The collector installs as a service; no console gymnastics needed.

  Windows may first show "Windows protected your PC" or a browser warning,
  because the file is a script downloaded from the internet and is not
  code-signed. Choose "More info" -> "Run anyway".

  Prefer the command line? From cmd or PowerShell, in this folder:
      .\install-selenne-agent.cmd

WHAT IT DOES
------------
  Installs the Wazuh agent (about 13 MB download, 47 MB on disk) and enrols it
  with your Selenne account. From then on the machine's security events are
  shipped to https://__MANAGER__ and appear in Live Alerts within a minute.

  Nothing is analysed on this computer: no models, no Python, no scanning.
  Detection, ML scoring and the AI analyst all run on the Selenne server.

  Running it again on a machine that already has the agent re-enrols it rather
  than installing a second copy.

AFTER INSTALL
-------------
  Start Menu -> Selenne          opens your dashboard
  services.msc -> Wazuh          the collector service (starts automatically)
  C:\Program Files (x86)\ossec-agent\ossec.log      agent log, if it misbehaves

UNINSTALL
---------
  Settings -> Apps -> Installed apps -> Wazuh Agent -> Uninstall.
  Then delete the "Selenne" Start Menu entry if it is still there.

KEEP THIS FILE PRIVATE
----------------------
  install-selenne-agent.cmd carries the enrolment password for the __OWNER__
  account. Anyone who has it can register endpoints against your dashboard, so
  do not share the package or commit it anywhere public.
