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

import com.alibaba.nacos.client.config.http.ServerHttpAgent;
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
public class ConfigSpasAuthenticationFilter extends OncePerRequestFilter {
    private UserDetailsService userDetailsService;

    public ConfigSpasAuthenticationFilter(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        String accessKey = request.getHeader(ServerHttpAgent.HEADER_SPAS_ACCESS_KEY);
        String signature = request.getHeader(SpasAdapter.HEADER_SPAS_SIGNATURE);
        if (StringUtils.hasText(accessKey) && StringUtils.hasText(signature)) {
            UserDetails user = userDetailsService.loadUserByUsername(accessKey);
            String timestamp = request.getHeader(SpasAdapter.HEADER_TIMESTAMP);
            String resource = SpasAdapter.getResource(request.getParameter(SpasAdapter.TENANT_KEY),
                request.getParameter(SpasAdapter.GROUP_KEY));

            if (signature.equals(SpasAdapter.sign(resource, timestamp, user.getPassword()))) {
                fillSecurityContext(user);
                chain.doFilter(request, response);
                return;
            }else{
                System.out.println("ConfigSpasAuthenticationFilter: 认证是失败");
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
