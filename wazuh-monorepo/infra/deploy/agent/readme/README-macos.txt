===============================================================================
  SELENNE - endpoint collector for macOS
  Account: __OWNER__          Dashboard: https://__DASHBOARD__
===============================================================================

WHAT IS IN THIS PACKAGE
-----------------------
  install-selenne-collector-macos.sh   The installer (Apple Silicon + Intel).
  selenne-logo.png                     Selenne logo (512x512), for your own use.
  README.txt                           This file.

INSTALL
-------
  Open Terminal in the unzipped folder and run:

      sudo bash install-selenne-collector-macos.sh

  It needs administrator rights because the collector installs as a launchd
  service under /Library/Ossec.

  macOS may need to be told the collector can read logs: if events do not show
  up, grant Full Disk Access to /Library/Ossec/bin/wazuh-agentd under
  System Settings -> Privacy & Security -> Full Disk Access.

WHAT IT DOES
------------
  Installs the Wazuh agent (~13 MB) and enrols it with your Selenne account.
  From then on this Mac's security events are shipped to https://__DASHBOARD__
  and appear in Live Alerts within a minute.

  Nothing is analysed locally: no models, no scanning. Detection, ML scoring
  and the AI analyst all run on the Selenne server.

  Running it again on a Mac that already has the collector re-enrols it rather
  than installing a second copy.

AFTER INSTALL
-------------
  sudo /Library/Ossec/bin/wazuh-control status     service state
  /Library/Ossec/logs/ossec.log                    collector log
  /Library/Ossec/etc/ossec.conf                    what is being collected

UNINSTALL
---------
  sudo /Library/Ossec/bin/wazuh-control stop
  sudo /bin/rm -r /Library/Ossec

KEEP THIS FILE PRIVATE
----------------------
  install-selenne-collector-macos.sh carries the enrolment password for the
  __OWNER__ account. Anyone who has it can register endpoints against your
  dashboard, so do not share the package or commit it anywhere public.
