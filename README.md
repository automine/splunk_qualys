# Apps for Getting Qualysguard Data into Splunk
There are two apps here:

## IA-qualysguard_scan
This is the input app (IA). It can be deployed by deployment server. Note that password is not encrypted in the configuration files.

## TA-qualysguard_scan
This is the parsing for the events generated by the IA app. This should go on IDX, HF and SH.