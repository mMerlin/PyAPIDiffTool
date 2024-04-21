# PyAPIDiffTool

PyAPIDiffTool is a Python utility designed to compare the Application Programming Interfaces (APIs) of two Python modules. It provides detailed insights into differences in module interfaces, which is crucial for ensuring compatibility between different Python implementations, such as between standard Python and CircuitPython.

## Features

- Compare attributes and methods between two modules.
- Configurable attribute scopes (all, public, published).
- Customizable reports for matched attributes, not implemented attributes, extensions, and skipped attributes.
- Supports ignoring specific attributes, docstrings, and added annotations based on context.
- Generate a configuration file with default settings.
- Command-line interface for easy integration into development workflows.

## Installation

PyAPIDiffTool uses pipenv for managing its environment and dependencies. Ensure you have pipenv installed on your system. If not, you can install it via pip:

```bash
pip install pipenv
```

Clone this repository to your local machine:

```bash
git clone https://github.com/mMerlin/PyAPIDiffTool.git
```

Navigate to the cloned directory and install dependencies:

```bash
cd PyAPIDiffTool
```

To set up the project environment and install development dependencies such as pylint, use:

```bash
pipenv install --dev
```

To just run the application, no dependencies need to be installed (the pipenv environment does need to be initialized though). However all modules to be compared, and their dependencies, must be accessible. For many CircuitPython modules, the source can be downloaded and placed anywhere in the search path. They do not need to be installed. Some dependencies though need to actually be installed in the environment. 'pipenv install' will include the adafruit-blinka package to cover a lot of common dependencies. Other discovered dependencies will need to be installed manually.

```bash
pipenv install «package_name»
```

The source for many CircuitPython packages can be downloaded manually, and placed anywhere in the search path. A simpler method is to use circup, which is install in the virtual environment if 'pipenv install --dev' is used.

To load the adafruit_logging library to the lib folder of the current directory, you can use something like.

```bash
circup --path "." --board-id "pyportal" --cpy-version "9.0.4" install --py adafruit_logging
```

You should be able to use any valid board-id. The latest (stable) CircuitPython version is best. If you are working with a specific board and CircuitPython version, use that.

## Usage

Run PyAPIDiffTool using the following command. Make sure the virtual python environment is active first.

```bash
python py_api_diff_tool.py [options] base_module_path port_module_path
```

## Basic Example

Compare the API of two modules. The intended use would be a base (standard CPython) and port (CircuitPython) module, but other cases will work (or at least try to work) as well.

```bash
cd PyAPIDiffTool
pipenv shell
python py_api_diff_tool.py logging adafruit_logging
```

The application adds the lib folder to the search path, so it is not necessary to either cd to lib, or specify lib.adafruit_logging for the module path.

## Options

- --version - Display the program's version.
- --generate-rcfile - Generate a default configuration file.
- --attribute-scope {all,public,published} - Scope of attributes to compare.

More detailed options are provided in the help output below. Also see --generate-rcfile output for argument usage information.

## Help Output

```text
usage: py_api_diff_tool.py [-h] [--version] [--generate-rcfile] [--attribute-scope {all,public,published}]
                           [--logging-level {DEBUG,INFO,WARN,ERROR,CRITICAL}] [--report-exact-match]
                           [--use-builtin-filters] [--ignore-module-attributes MODULE_ATTRIBUTES]
                           [--ignore-global-attributes GLOBAL_ATTRIBUTES] [--ignore-class-attributes CLASS_ATTRIBUTES]
                           [--ignore-docstring CONTEXTS] [--ignore-added-annotations CONTEXTS] [--report-matched]
                           [--report-not-implemented] [--report-extensions] [--report-skipped] [--config-file CONFIG_FILE]
                           [--no-user-config] [--no-project-config]
                           base_module_path port_module_path

Compare module APIs.

positional arguments:
  base_module_path      Dot notation path for the base module (e.g., "os.path").
  port_module_path      Dot notation path for the port module (e.g., "mypackage.mymodule").

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  --generate-rcfile     Generate a sample configuration file with default settings and exit
  --attribute-scope {all,public,published}
                        Scope of attributes to compare.
  --logging-level {DEBUG,INFO,WARN,ERROR,CRITICAL}
                        Level to start logging at.
  --report-exact-match  Include attributes with exact matches in report. (negate with --noreport-exact-match)
  --use-builtin-filters
                        Include builtin attribute names in context exclusions. (negate with --nouse-builtin-filters)
  --ignore-module-attributes MODULE_ATTRIBUTES
                        Comma-separated list of attributes to ignore in module context. Surround list with quotes if spaces
                        included after commas.
  --ignore-global-attributes GLOBAL_ATTRIBUTES
                        Comma-separated list of attributes to ignore in all contexts. Surround list with quotes if spaces
                        included after commas.
  --ignore-class-attributes CLASS_ATTRIBUTES
                        Comma-separated list of attributes to ignore in class context. Surround list with quotes if spaces
                        included after commas.
  --ignore-docstring CONTEXTS
                        Specify contexts to ignore docstring changes in: 'all' or comma-separated list of contexts {class,
                        module, method}. Use 'no-<context>' to exclude (not ignore). Surround list with quotes if spaces
                        included after commas.
  --ignore-added-annotations CONTEXTS
                        Specify contexts to ignore added annotations: 'all' or comma-separated list of contexts {scope,
                        parameter, return}. Use 'no-<context>' to exclude (not ignore). Surround list with quotes if spaces
                        included after commas.
  --report-matched      Generate report for differences in matched attributes. (negate with --noreport-matched)
  --report-not-implemented
                        Generate report for attributes not implemented in the port. (negate with --noreport-not-implemented)
  --report-extensions   Generate report for extensions implemented in the port. (negate with --noreport-extensions)
  --report-skipped      Generate report for attributes that were skipped. (negate with --noreport-skipped)
  --config-file CONFIG_FILE
                        Specify a configuration file to load.
  --no-user-config      Do not load the user configuration file.
  --no-project-config   Do not load the project configuration file.
```

## Configuration

You can customize PyAPIDiffTool by using a configuration files. Use the --generate-rcfile option to create a sample configuration file which you can then modify according to your needs. Use --config-file <file_path> to use a specific file. By default, without --no-use-config and --no-project-config, 2 configuration files are looked for and loaded (if found). One for the user in .config/py_api_diff_tool/py_api_diff_tool.ini, the other in the current  folder. The content of each configuration file is merged with the result after the previous configuration file. This alters the previous settings, but either replacing with a new value (for on/off settings), or updates with new values (the ignore fields)

## Contributing

Contributions are welcome! Please read CONTRIBUTING.md for details on our code of conduct and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Thanks to everyone who contributed to making this tool better! For starters, ChatGPT 4 was used as a coding assistant and code reviewer.
