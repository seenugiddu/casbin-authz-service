package com.example.authz.config;

import org.casbin.jcasbin.main.Enforcer;
import org.casbin.jcasbin.model.Model;
import org.casbin.jcasbin.persist.file_adapter.FileAdapter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * Builds the jCasbin {@link Enforcer} from the model and policy files declared in
 * application.yml. Both are read as Spring {@link Resource}s so they work from the
 * classpath, the file system (file:/etc/authz/policy.csv) or a URL.
 *
 * To move policies to a database, replace the {@link FileAdapter} with e.g.
 * org.casbin:jdbc-adapter and keep the rest of the service untouched.
 */
@Configuration
public class CasbinConfig {

    @Bean
    public Enforcer enforcer(AuthzProperties properties) throws IOException {
        Resource modelResource = properties.casbin().model();
        Resource policyResource = properties.casbin().policy();

        Model model = new Model();
        try (InputStream in = modelResource.getInputStream()) {
            model.loadModelFromText(new String(in.readAllBytes(), StandardCharsets.UTF_8));
        }

        try (InputStream in = policyResource.getInputStream()) {
            Enforcer enforcer = new Enforcer(model, new FileAdapter(in));
            // Policies are read-only in this service; never write back to the file.
            enforcer.enableAutoSave(false);
            return enforcer;
        }
    }
}
