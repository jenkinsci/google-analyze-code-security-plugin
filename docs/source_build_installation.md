<!--
 Copyright 2024 Google LLC

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
-->

# Plugin Source Build Installation


Use these instructions to build and install the Google Analyze Code Security plugin from source files.


1. Clone the plugin and enter the directory:
    ```bash
     git clone git@github.com:jenkinsci/google-analyze-code-security-plugin.git
     cd google-analyze-code-security-plugin
    ```
1. Check out the branch that you want to build from:
   ```bash
     git checkout <branch name>
    ```
1. Build the plugin into a .hpi plugin file. When running a build for the first time, build the package using the Maven clean package command. Run goals:
    ```bash
     mvn clean package
    ```
1. Run the hpi command:
    ```bash
     mvn hpi:hpi
     ```
1. In the Jenkins console, click **Manage Jenkins** > **Manage Plugins**.
1. In the **Plugin Manager**, click the **Advanced** tab. In the **Upload Plugin** section, click **Choose File**.
1. Choose the Jenkins plugin file that you built in Step 3.
1. Click **Upload**.