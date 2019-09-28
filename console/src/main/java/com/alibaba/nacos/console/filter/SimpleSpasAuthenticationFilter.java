/*
 * Copyright 1999-2018 Alibaba Group Holding Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.alibaba.nacos.console.filter;

import com.alibaba.nacos.client.config.impl.SpasAdapter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;

/**
 * spas auth filter
 *
 * @author CharlesHe
 */
public class SimpleSpasAuthenticationFilter extends OncePerRequestFilter {
    private UserDetailsService userDetailsService;

    public SimpleSpasAuthenticationFilter(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {

        String[] securityTokens = StringUtils.split(request.getHeader("Spas-SecurityToken"), ":");
        if (securityTokens != null && securityTokens.length == 2) {
            UserDetails user = userDetailsService.loadUserByUsername(securityTokens[0]);
            if (user.getPassword().equals(securityTokens[1])) {
                fillSecurityContext(user);
                chain.doFilter(request, response);
                return;
            }
        }

        String accessKey = request.getHeader("Spas-AccessKey");
        String signature = request.getHeader("Spas-Signature");
        if (StringUtils.hasText(accessKey) && StringUtils.hasText(signature)) {
            UserDetails user = userDetailsService.loadUserByUsername(accessKey);
            String timestamp = request.getHeader("Timestamp");

            String resource = null;
            String tenant = request.getParameter("tenant");
            String group = request.getParameter("group");
            if (StringUtils.hasText(tenant) && StringUtils.hasText(group)) {
                resource = tenant + "+" + group;
            } else if (StringUtils.hasText(group)) {
                resource = group;
            }

            boolean isSignatureMath = false;
            if (StringUtils.hasText(resource)) {
                isSignatureMath = signature.equals(SpasAdapter.signWithhmacSHA1Encrypt(timestamp, user.getPassword()));
            } else {
                isSignatureMath = signature.equals(SpasAdapter.signWithhmacSHA1Encrypt(resource + "+" + timestamp, user.getPassword()));
            }

            if (isSignatureMath) {
                fillSecurityContext(user);
                chain.doFilter(request, response);
                return;
            }
        }

        chain.doFilter(request, response);
    }

    private void fillSecurityContext(UserDetails user) {
        User principal = new User(user.getUsername(), "", Collections.emptyList());
        Authentication authentication = new UsernamePasswordAuthenticationToken(principal, "", Collections.emptyList());

        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}
