===============================================================================
  SELENNE - endpoint collector for Linux
  Account: __OWNER__          Dashboard: https://__MANAGER__
===============================================================================

WHAT IS IN THIS PACKAGE
-----------------------
  install-selenne-collector.sh   The installer.
  selenne-logo.png               Selenne logo (512x512), for your own use.
  README.txt                     This file.

INSTALL
-------
  Debian/Ubuntu, RHEL/Fedora and SUSE are all handled by the same script:

      unzip selenne-collector-linux.zip
      sudo bash install-selenne-collector.sh

  It needs root because the collector installs as a systemd service.

WHAT IT DOES
------------
  Installs the Wazuh agent (~13 MB) and enrols it with your Selenne account.
  From then on this machine's security events are shipped to
  https://__MANAGER__ and appear in Live Alerts within a minute.

  Nothing is analysed locally: no models, no scanning. Detection, ML scoring
  and the AI analyst all run on the Selenne server.

  Running it again on a machine that already has the collector re-enrols it
  rather than installing a second copy.

AFTER INSTALL
-------------
  systemctl status wazuh-agent      service state
  /var/ossec/logs/ossec.log         collector log, if it misbehaves
  /var/ossec/etc/ossec.conf         what is being collected

UNINSTALL
---------
  sudo systemctl stop wazuh-agent
  sudo apt-get remove wazuh-agent     (or: dnf/yum/zypper remove wazuh-agent)

KEEP THIS FILE PRIVATE
----------------------
  install-selenne-collector.sh carries the enrolment password for the __OWNER__
  account. Anyone who has it can register endpoints against your dashboard, so
  do not share the package or commit it anywhere public.
