# PyAPIDiffTool Known Issues

- 2024/04/20 No unit test suite.

Doing this 'properly' is likely more work than spent on the project to date.

It really should get started, and whittled down as time permits. Those darn *priorities*.

- 2024/04/20 introspection_tools limitations

The existing code supports the needs of the current application, but there are known cases where infinite recursion and crashes can occur if used outside of those constraints. The functions need to be more robust. A test suite to exercise them, and establish the limits would be a big step.

- 2024/04/20 user configuration file path is linux centric

This should not prevent running in other environments. It just means that the (optional) user configuration file is not going to be found. At least in the 'normal' location for the operating system.
