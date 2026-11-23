/*******************************************************************************
 * Copyright (c) 2026 RISE and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 *
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 *
 * Contributors:
 *     Rikard Höglund (RISE) - initial implementation
 *******************************************************************************/
package org.eclipse.leshan.server.bootstrap.demo;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/**
 * (Same class exists in leshan-server-demo; leshan-core cannot use java.nio.file, Android API 19.)
 * Helpers to write files so that a crash of the process never leaves a partially written file behind.
 */
public final class AtomicFiles {

    /** Suffix of the temporary files used while writing. Loaders should ignore such files. */
    public static final String TMP_SUFFIX = ".tmp";

    private AtomicFiles() {
    }

    /**
     * Atomically replaces the content of {@code target} with {@code content}
     *
     * The content is first written to a temporary file in the same directory, which is then renamed over the target.
     * Readers therefore always see either the old or the new complete file, even if the process crashes during the
     * write.
     */
    public static void write(Path target, String content) throws IOException {
        Path dir = target.toAbsolutePath().getParent();
        Files.createDirectories(dir);

        // Unique temporary file, so concurrent writers of the same target do not collide
        Path tmp = Files.createTempFile(dir, target.getFileName().toString() + ".", TMP_SUFFIX);
        try {
            Files.write(tmp, content.getBytes(StandardCharsets.UTF_8));
            try {
                Files.move(tmp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(tmp);
        }
    }
}
