# Patchnotes

## V0.1.2
* Fixes the install and use of the nfc drivers

## V0.1.1
* bugfixes
    * Reader main_loop can receive new select command at any time (not just at the start of a session).
    * Invalid keys raise an error and return a error response during auth0
    * Fixed some errors not being raised correctly
    * Corrected salt generation, now includes proprietary information and correct numbers
* Changed TLV implementation, better handling of edge cases
* Added more tests, using the testvectors
* Updated AID
* Updated to spec version 0.7.3
* Added documentation

## V0.1.0
* Initial release
* Transport protocols
    * NFC transport protocol supported
    * socket transport protocol supported (not official, only for testing purposes)
* Access protocols
    * Expedited Phase (standard) supported
