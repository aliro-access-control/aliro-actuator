.. Aliro_Actuator documentation master file, created by
   sphinx-quickstart on Wed Aug 30 11:16:16 2023.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to Aliro_Actuator's documentation!
==========================================

The code is separated into 5 parts: the 4 parts as described in the Architecture
overview of the specification (chapter 5.1) and the hardware drivers.

This actuator supports both the reader side and the user side of the protocol. The class
that implements the reader side is the 
:py:class:`~aliro_actuator.access_protocol.reader.Reader`, and the user side is 
implemented by the :py:class:`~aliro_actuator.access_protocol.user_device.UserDevice`.

Both :py:class:`~aliro_actuator.access_protocol.reader.Reader` and 
:py:class:`~aliro_actuator.access_protocol.user_device.UserDevice` have a similar structure. 
They both have a parameter transport_protocol (of type :py:class:`~aliro_actuator.access_protocol.defines.TransportProtocol`)
which indicates which transport protocol to use (NFC or BLE/UWB). After instantiating 
the class, the :py:meth:`~aliro_actuator.access_protocol.user_device.UserDevice.transaction_initiation` 
or :py:meth:`~aliro_actuator.access_protocol.reader.Reader.transaction_initiation` method 
is used to set up the connection to a device. 
This method blocks until the connection is established.

The :py:class:`~aliro_actuator.access_protocol.user_device.UserDevice` and 
:py:class:`~aliro_actuator.access_protocol.reader.Reader` can now be used in one of 
two ways: using the handle functions for an easy to use approach, or the command/response 
methods for more control.

Approach 1 (handle)
-------------------
This approach uses the attributes set during instantation, and the ones received from 
commands, to make the actuator easier to use. Start by using the 
:py:meth:`~aliro_actuator.access_protocol.user_device.UserDevice.start_new_session` or 
:py:meth:`~aliro_actuator.access_protocol.user_device.Reader.start_new_session`
to start a session. All data received will be stored in this session. 
The :py:class:`~aliro_actuator.access_protocol.user_device.UserDevice` now needs to wait 
for a command. This is done with the 
:py:meth:`~aliro_actuator.access_protocol.user_device.UserDevice.wait_for_command` method, 
which returns a :py:class:`~aliro_actuator.access_protocol.apdu.Command` to pass to a handle method.  
Now, use the methods that start with 'handle' to handle the commands:

| User methods:  
| :py:meth:`~aliro_actuator.access_protocol.user_device.UserDevice.handle_select`
| :py:meth:`~aliro_actuator.access_protocol.user_device.UserDevice.handle_auth0`
| :py:meth:`~aliro_actuator.access_protocol.user_device.UserDevice.handle_auth1`
| :py:meth:`~aliro_actuator.access_protocol.user_device.UserDevice.handle_control_flow`
| :py:meth:`~aliro_actuator.access_protocol.user_device.UserDevice.handle_exchange`
| :py:meth:`~aliro_actuator.access_protocol.user_device.UserDevice.handle_load_cert`

| Reader methods:  
| :py:meth:`~aliro_actuator.access_protocol.reader.Reader.handle_select`
| :py:meth:`~aliro_actuator.access_protocol.reader.Reader.handle_auth0`
| :py:meth:`~aliro_actuator.access_protocol.reader.Reader.handle_auth1`
| :py:meth:`~aliro_actuator.access_protocol.reader.Reader.handle_control_flow`
| :py:meth:`~aliro_actuator.access_protocol.reader.Reader.handle_exchange`
| :py:meth:`~aliro_actuator.access_protocol.reader.Reader.handle_load_cert`

Approach 2 (command/response)
-----------------------------
This approach gives more control to the programmer. The methods that start with 
'command'/'response' require a value for every piece of data they will send. The data 
received will also need to be manually processed by the programmer (unlike Approach 1, 
there is no session to save received data). 
Note that Approach 1 also uses these 'command'/'response' methods, so you can use the 
Approach 1 methods as an example.

Modules
=======

.. toctree::
   :maxdepth: 4
   :caption: Modules

   modules

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
