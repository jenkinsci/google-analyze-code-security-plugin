/*
 * Copyright 2024 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.jenkins.plugins.google.analyze.code.security.utils;

import hudson.FilePath;
import io.jenkins.plugins.google.analyze.code.security.CodeScanBuildStep;
import io.jenkins.plugins.google.analyze.code.security.commons.CustomerMessage;
import io.jenkins.plugins.google.analyze.code.security.model.FileInfo;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.Queue;
import java.util.stream.Collectors;
import lombok.NonNull;
import org.antlr.v4.runtime.misc.Pair;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;

/**
 * Utility class for report generation helper methods.
 */
public final class FileUtils {

    private FileUtils() {}

    /**
     *  Finds file in the workspace and reads its contents.
     *
     * @param root base directory of the jenkins workspace.
     * @param fileName file name.
     * @param filePath file path relative to workspace root directory.
     * @return file info comprising file contents and file path.
     * @throws IOException exception occurred during reading file.
     * @throws InterruptedException thrown when execution thread is interrupted.
     */
    public static FileInfo loadFileFromWorkspace(
            @NonNull final FilePath root, @NonNull final String fileName, final String filePath)
            throws IOException, InterruptedException {
        if (!StringUtils.isEmpty(filePath)) {
            return FileInfo.builder()
                    .file(IOUtils.toByteArray(
                            root.child(/*relOrAbsolute=*/ filePath + fileName).read()))
                    .path(filePath + fileName)
                    .build();
        }

        // BFS implementation where we scan by level all recursive children of the directory.
        // Add all items in dir to the queue and then evaluating each item if it's a directory
        // add its children to the queue else if it's a file, check if it matches request fileName.
        // Maintain path from the root(rootDir) to the leaf(targetFile) while scanning the directory.
        final Queue<Pair<FilePath, List<String>>> pathDir = new ArrayDeque<>();
        // add root dir and path placeHolder
        pathDir.add(new Pair<>(root, new ArrayList<>()));
        while (!pathDir.isEmpty()) {
            Pair<FilePath, List<String>> fileInfo = pathDir.poll();
            FilePath path = fileInfo.a;
            // path from root to current item.
            List<String> pathTracker = new ArrayList<>(fileInfo.b);
            pathTracker.add(path.getName());
            if (path.isDirectory()) {
                // add all children along with path to the queue.
                pathDir.addAll(path.list().stream()
                        .map((child) -> new Pair<>(child, pathTracker))
                        .collect(Collectors.toList()));
            } else if (path.getName().matches(fileName)) {
                // target file is found return file contents and path root to the file.
                return FileInfo.builder()
                        .file(IOUtils.toByteArray(path.read()))
                        .path(StringUtils.join(pathTracker, "/"))
                        .build();
            }
        }
        throw new IllegalArgumentException(CustomerMessage.FILE_NOT_FOUND);
    }

    /**
     * Reads a resource present on the resource directory.
     *
     * @param filePath location of the file w.r.t. resource directory in the project.
     * @return file contents as string.
     * @throws IOException if the file is not found on the path.
     */
    public static String readResource(final String filePath) throws IOException {
        try (InputStream in = CodeScanBuildStep.class.getResourceAsStream(filePath)) {
            return readFromInputStream(in);
        }
    }

    /**
     * Reads stream contents and returns them as string.
     *
     * @throws IOException if failure occurs while reading stream contents.
     */
    public static String readFromInputStream(final InputStream inputStream) throws IOException {
        final StringBuilder resultStringBuilder = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {
            String line;
            while ((line = br.readLine()) != null) {
                resultStringBuilder.append(line).append("\n");
            }
        }
        return resultStringBuilder.toString();
    }
}
