# **VISTA: Vulnerability Identification using Semantic and Textual Analysis**

VISTA is a tool designed to analyze and track vulnerabilities in software systems. It provides advanced features for commit analysis, static code inspection, and comprehensive vulnerability reporting. This tool leverages **srcML** and **CppCheck** for parsing and static analysis and integrates advanced techniques to label and classify vulnerabilities across software projects.

[![Run Tests Units](https://github.com/M12Shehab/VISTA-Producation/actions/workflows/run_tests.yml/badge.svg)](https://github.com/M12Shehab/VISTA-Producation/actions/workflows/run_tests.yml)
---

## **Features**
- Automatically processes commits and labels vulnerabilities using traditional and advanced SZZ (Scalable and Simple Zeroing) techniques.
- Integrates static code analysis using **CppCheck**.
- Interfaces with the **NVD API** to fetch and process vulnerability data.
- Provides FAIR-compliant datasets for reproducibility.
- Easily extensible for custom project analysis.

---

## **Installation**

### **1. Pre-requisites**
Ensure you have the following installed on your system:
- **Python 3.7+**
- **srcML** ([Download srcML](https://www.srcml.org/#download))
- **CppCheck** ([Download CppCheck](https://cppcheck.sourceforge.io/))
- **Git** ([Download Git](https://git-scm.com/))
- **NVD** API Key ([Get NVD API Key](https://nvd.nist.gov/developers/request-an-api-key))

### **2. Install srcML**
1. Download the installer from [srcML Download](https://www.srcml.org/#download).
2. Install srcML and add its installation directory to your system's environment `Path`.
    - Example: Add `C:\Program Files\srcML\` to the `Path` variable.
3. Verify installation by running:
   ```bash
   srcml --version
    ```

### **3. Install CppCheck**
1. Download the installer from CppCheck Download.
2. Install CppCheck and add its installation directory to your system's environment Path.
   - Example: Add C:\Program Files\CppCheck\ to the Path variable.
3. Verify installation by running:
   ```bash
   cppcheck --version
   ```

### **4. Set up the Python Environment**
1. Clone the repository:
    ```bash
    git clone https://github.com/M12Shehab/vista.git
    cd vista
   ```
2. Create a virtual environment (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/macOS
   venv\Scripts\activate     # Windows
   ```
3. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Verify the installation by running:
   ```bash
   python src/vista.py --help
   ```
### **5.Tool Configuration**
1. **Edit the config.json File:**
   Before running the tool, update the config.json file located in the root directory with your project-specific configuration. Here’s an example structure:
    ```json
    {
   "project_name": "impala",
   "code_repository_path": "C:/Users/USER-NAME/Downloads/impala",
   "repo_url": "https://github.com/apache/impala.git",
   "repository_branch": "main",
   "file_ext_to_parse": ["cpp", "c", "h", "hpp"],
   "num_workers": 1,
   "nvd_api_key": "ADD_YOUR_NVD_API_KEY"
   }
    ```
2. **Fields to Update**
   - **project_name**: Name of the project to analyze (e.g., impala).
   - **code_repository_path**: Absolute path to the repository on your local machine.
   - **repo_url**: URL of the Git repository to clone.
   - **repository_branch**: Branch to analyze (e.g., main).
   - **file_ext_to_parse**: List of file extensions to include in the analysis (e.g., .cpp, .c).
   - **num_workers**: Number of parallel workers for processing commits.
   - **nvd_api_key**: Your API key for the NVD API. See the next section for setup.

---
## **Dataset Setup**
1. Download the dataset from [Zenodo](https://zenodo.org/records/14210160).
2. Extract the dataset to the `data` directory in the project root.
3. Copy the extracted `data` directory to the `vista` directory. 
4. Be sure the `data` directory is in the same directory as the `vista.py` file as shown below:
    ```bash
    vista
    ├── data
    │   ├── impala
    │   │   ├── ...
    │   ├── arrow
    │   │   ├── ...
    │   ├── mesos
    │   │   ├── ...
    ├── modules
    │   ├── ...
    ├── config.json
    ├── requirements.txt
    ├── vista.py
    ```
5. The dataset is now ready for use with the tool. In case you want to use your own dataset, be sure to update the `config.json` file with the correct paths and set up the NVD API key.

---
## **Usage**
1. Run the tool using the following command:
    ```bash
    python vista.py
    ```
2. Clone or access the repository specified in **config.json**
3. The tool will start processing the commits and vulnerabilities. The output will be saved in the `data/{project_name}/` directory.

---
## **Acknowledgements**
This tool leverages:
- srcML
- CppCheck
- NVD API


