/*******************************************************************************
 * Copyright (c) 2013-2015 Sierra Wireless and others.
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
 *     Sierra Wireless - initial API and implementation
 *     Achim Kraus (Bosch Software Innovations GmbH) - add json as storage format
 *     Rikard Höglund (RISE) - one file per endpoint, atomic writes
 *******************************************************************************/
package org.eclipse.leshan.server.bootstrap.demo;

import java.io.IOException;
import java.io.Reader;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.EnumSet;
import java.util.Map;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import org.eclipse.leshan.core.request.BindingMode;
import org.eclipse.leshan.core.util.Hex;
import org.eclipse.leshan.core.util.Validate;
import org.eclipse.leshan.server.bootstrap.BootstrapConfig;
import org.eclipse.leshan.server.bootstrap.EditableBootstrapConfigStore;
import org.eclipse.leshan.server.bootstrap.InMemoryBootstrapConfigStore;
import org.eclipse.leshan.server.bootstrap.InvalidConfigurationException;
import org.eclipse.leshan.server.bootstrap.demo.json.BindingModeTypeAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

/**
 * A {@link EditableBootstrapConfigStore} which persists configurations using json format, one file per endpoint in a
 * directory.
 * <p>
 * Each add/remove only writes (or deletes) the file of that endpoint, so the cost does not grow with the number of
 * stored configurations. Files are written atomically (see {@link AtomicFiles}).
 * <p>
 * A configuration file from older versions (all endpoints in one json file, e.g. data/bootstrap.json) is imported
 * once at startup and then renamed to *.migrated.
 */
public class JSONFileBootstrapStore extends InMemoryBootstrapConfigStore {

    private static final Logger LOG = LoggerFactory.getLogger(JSONFileBootstrapStore.class);

    // lock for the two maps
    private final ReadWriteLock readWriteLock = new ReentrantReadWriteLock();
    private final Lock readLock = readWriteLock.readLock();
    private final Lock writeLock = readWriteLock.writeLock();

    // default location for persistence
    public static final String DEFAULT_DIRECTORY = "data/bootstrap";

    private static final String FILE_SUFFIX = ".json";
    // Keep file names well below common file system limits (255 bytes)
    private static final int MAX_HEX_NAME_LENGTH = 200;

    private final Path directory;
    private final Path legacyFile;
    private final Gson gson;

    /** Content of a per-endpoint file. The endpoint name is stored here; the file name is only an encoding of it. */
    private static class EndpointConfigFile {
        String endpoint;
        BootstrapConfig config;

        EndpointConfigFile(String endpoint, BootstrapConfig config) {
            this.endpoint = endpoint;
            this.config = config;
        }
    }

    public JSONFileBootstrapStore() {
        this(DEFAULT_DIRECTORY);
    }

    /**
     * @param location the directory in which to persist the configurations. For backwards compatibility a path
     *        ending in ".json" (the old single-file format) is also accepted: the directory is then that path without
     *        ".json", and the file itself is imported if it exists.
     */
    public JSONFileBootstrapStore(String location) {
        Validate.notEmpty(location);
        GsonBuilder builder = new GsonBuilder();
        builder.setPrettyPrinting();
        builder.registerTypeAdapter(new TypeToken<EnumSet<BindingMode>>() {
        }.getType(), new BindingModeTypeAdapter());
        this.gson = builder.create();

        if (location.endsWith(FILE_SUFFIX)) {
            this.directory = Paths.get(location.substring(0, location.length() - FILE_SUFFIX.length()));
            this.legacyFile = Paths.get(location);
        } else {
            this.directory = Paths.get(location);
            this.legacyFile = Paths.get(location + FILE_SUFFIX);
        }

        loadFromDirectory();
        migrateLegacyFile();
    }

    @Override
    public Map<String, BootstrapConfig> getAll() {
        readLock.lock();
        try {
            return super.getAll();
        } finally {
            readLock.unlock();
        }
    }

    public void addToStore(String endpoint, BootstrapConfig config) throws InvalidConfigurationException {
        super.add(endpoint, config);
    }

    @Override
    public void add(String endpoint, BootstrapConfig config) throws InvalidConfigurationException {
        writeLock.lock();
        try {
            addToStore(endpoint, config);
            // Save what is actually stored (add() may merge with an existing config)
            saveEndpoint(endpoint, super.getAll().get(endpoint));
        } finally {
            writeLock.unlock();
        }
    }

    @Override
    public BootstrapConfig remove(String endpoint) {
        writeLock.lock();
        try {
            BootstrapConfig res = super.remove(endpoint);
            deleteEndpoint(endpoint);
            return res;
        } finally {
            writeLock.unlock();
        }
    }

    // /////// File persistence

    /**
     * File name for an endpoint: the hex encoding of its UTF-8 name, which is collision free and safe for any
     * characters. Very long names fall back to a SHA-256 hash of the name.
     */
    Path fileFor(String endpoint) {
        byte[] name = endpoint.getBytes(StandardCharsets.UTF_8);
        String hex = Hex.encodeHexString(name);
        if (hex.length() > MAX_HEX_NAME_LENGTH) {
            try {
                hex = "sha256-" + Hex.encodeHexString(MessageDigest.getInstance("SHA-256").digest(name));
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException(e);
            }
        }
        return directory.resolve(hex + FILE_SUFFIX);
    }

    private void saveEndpoint(String endpoint, BootstrapConfig config) {
        try {
            AtomicFiles.write(fileFor(endpoint), gson.toJson(new EndpointConfigFile(endpoint, config)));
        } catch (Exception e) {
            LOG.error("Could not save bootstrap config of {} to file", endpoint, e);
        }
    }

    private void deleteEndpoint(String endpoint) {
        try {
            Files.deleteIfExists(fileFor(endpoint));
        } catch (IOException e) {
            LOG.error("Could not delete bootstrap config file of {}", endpoint, e);
        }
    }

    private void loadFromDirectory() {
        if (!Files.isDirectory(directory)) {
            return;
        }
        int loaded = 0;
        // Only *.json: leftover temporary files from interrupted writes are ignored
        try (DirectoryStream<Path> files = Files.newDirectoryStream(directory, "*" + FILE_SUFFIX)) {
            for (Path file : files) {
                // One bad file must not prevent loading the others
                try (Reader in = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
                    EndpointConfigFile content = gson.fromJson(in, EndpointConfigFile.class);
                    if (content == null || content.endpoint == null || content.config == null) {
                        LOG.error("Skipping invalid bootstrap config file {}", file);
                        continue;
                    }
                    addToStore(content.endpoint, content.config);
                    loaded++;
                } catch (Exception e) {
                    LOG.error("Skipping bootstrap config file {} which could not be loaded", file, e);
                }
            }
        } catch (IOException e) {
            LOG.error("Could not list bootstrap config directory {}", directory, e);
        }
        LOG.info("Loaded {} bootstrap configs from {}", loaded, directory);
    }

    /**
     * Import a configuration file in the old single-file format (if any), write the per-endpoint files and rename the
     * old file to *.migrated, so it is only imported once.
     */
    private void migrateLegacyFile() {
        if (!Files.isRegularFile(legacyFile)) {
            return;
        }
        Type type = new TypeToken<Map<String, BootstrapConfig>>() {
        }.getType();
        Map<String, BootstrapConfig> configs;
        try (Reader in = Files.newBufferedReader(legacyFile, StandardCharsets.UTF_8)) {
            configs = gson.fromJson(in, type);
        } catch (Exception e) {
            LOG.error("Could not read old bootstrap config file {}, leaving it untouched", legacyFile, e);
            return;
        }

        int imported = 0;
        if (configs != null) {
            for (Map.Entry<String, BootstrapConfig> entry : configs.entrySet()) {
                if (super.getAll().containsKey(entry.getKey())) {
                    // Already in the directory (e.g. an earlier import whose rename failed): the directory wins,
                    // and importing again would merge the config with itself
                    LOG.warn("Not importing {} from {}: already present in {}", entry.getKey(), legacyFile, directory);
                    continue;
                }
                try {
                    add(entry.getKey(), entry.getValue());
                    imported++;
                } catch (InvalidConfigurationException e) {
                    LOG.error("Could not import bootstrap config of {} from {}", entry.getKey(), legacyFile, e);
                }
            }
        }

        Path migrated = Paths.get(legacyFile.toString() + ".migrated");
        try {
            Files.move(legacyFile, migrated);
            LOG.info("Imported {} bootstrap configs from {} into {} (old file renamed to {})", imported, legacyFile,
                    directory, migrated);
        } catch (IOException e) {
            LOG.error("Imported {} bootstrap configs from {}, but could not rename it to {}", imported, legacyFile,
                    migrated, e);
        }
    }
}
