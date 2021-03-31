package com.yang.demo.config;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@EnableWebSecurity // 开启WebSecurity模式
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    // 访问权限约束
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 定制请求的授权规则
        // 首页所有人可以访问
        http.authorizeRequests().antMatchers("/").permitAll()
                // level1 下的所有请求，只有vip1才可以访问
                .antMatchers("/level1/**").hasRole("vip1")
                .antMatchers("/level2/**").hasRole("vip2")
                .antMatchers("/level3/**").hasRole("vip3");
        // 开启自动配置的登录功能
        // /login 请求来到登录页
        // 配置用户账号字段，密码字段
        // 当没有权限的时候默认进入登录页,进入自定义登录页
        // 自定义登录表单提交请求发送只login去请求处理
        http.formLogin()
                .usernameParameter("username")
                .passwordParameter("password")
                .loginPage("/toLogin")
                .loginProcessingUrl("/login");

        // 注销功能
        /* .deleteCookies(&quot;remove&quot;).invalidateHttpSession(false)
        *   删除cookies，清空session
        *   .logoutUrl(&quot;/custom-logout&quot;).logoutSuccessUrl(&quot;/logout-success&quot;);
        *   注销页面，有系统默认的也可以自己编写，注销成功跳转页面
        * */
        // 注销之后返回的页面的路径
        http.logout().logoutSuccessUrl("/");

        // 记住账号密码,存在浏览器的cookie里面,自定义记住登录账号密码参数
        http.rememberMe().rememberMeParameter("remember");
    }

    // 登录认证约束
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // inMemoryAuthentication 从内存拿,jdbcAuthentication在数据库拿
        //Spring security 5.0中新增了多种加密方式，也改变了密码的格式。
        //要想正常登陆，需要修改一下configure中的代码。要将前端传过来的密码进行某种方式加密
        //spring security 官方推荐的是使用bcrypt加密方式。
        // BCryptPasswordEncoder设置密码编码规则
        String pwd = new BCryptPasswordEncoder().encode("123456");
        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
                // 放置内存中的用户名、密码、角色
                .withUser("ywq").password(pwd).roles("vip2","vip3").and()
                .withUser("admin").password(pwd).roles("vip1","vip2","vip3").and()
                .withUser("guest").password(pwd).roles("vip3");
    }
}