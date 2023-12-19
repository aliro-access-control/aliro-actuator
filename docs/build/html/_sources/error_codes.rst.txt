Error Codes
===========


.. list-table:: Error codes
   :widths: 25 25 50
   :header-rows: 1

   * - Error
     - Error Code
     - ISO 7816 Tabel 7 meaning
   * - Command shorter than 4
     - 0x6701
     - Command APDU format not compliant with this standard
   * - CLA invalid
     - 0x6800
     - Functions in CLA not supported (no further information given)
   * - Invalid P1-P2
     - 0x6B00
     - Wrong parameters P1-P2 
   * - AID not found
     - 0x6A82
     - File or application not found
   * - Mandatory data not found in command
     - 0x6900
     - command not allowed (no further information given)
   * - Incorrect transaction state
     - 0x6985
     - Conditions of use not satisfied
   * - expedited_transaction_protocol_version is not supported
     - 0x6985
     - Conditions of use not satisfied
   * - format of data contained certificate_data is wrong
     - 0x6A80
     - Incorrect parameters in the command data field
   * - expedited-standard phase not allowed on this interface
     - 0x6985
     - Conditions of use not satisfied
   * - reader_sig is not verified
     - 0x6982
     - Security status not satisfied     
   * - Secure Channel Command Authentication failed
     - 0x6988
     - Incorrect secure messaging DO's
   * - cod.device_counter = 0x0000FFFF or cod.reader_counter = 0x0000FFFF
     - 0x6982
     - Security status not satisfied     
     