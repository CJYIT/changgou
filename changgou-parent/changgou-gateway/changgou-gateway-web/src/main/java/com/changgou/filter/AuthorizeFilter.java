package com.changgou.filter;
import com.changgou.util.JwtUtil;
import io.jsonwebtoken.Claims;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * 全局过滤器 :用于鉴权(获取令牌 解析 判断)     实现接口GlobalFilter和Ordered
 *
 * @author www.itcjy.com
 * @version 1.0
 * @package com.changgou.filter *
 * @since 1.0
 */
@Component
public class AuthorizeFilter implements GlobalFilter, Ordered {
    //定义令牌的参数名
    private static final String AUTHORIZE_TOKEN = "Authorization";
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        //1.获取请求对象
        ServerHttpRequest request = exchange.getRequest();
        //2.获取响应对象
        ServerHttpResponse response = exchange.getResponse();

        //true令牌在头文件中  false令牌不在头文件中->将令牌封装到头文件，再转递给其他微服务
        boolean hasToken = true;  //后面如果某种情况成立的话改变状态为false方便后面执行新的业务逻辑

        //3.判断 是否为登录的URL 如果是 放行
        if(request.getURI().getPath().startsWith("/api/user/login")){
            return chain.filter(exchange);
        }
        //4.判断 是否为登录的URL 如果不是      权限校验


        //4.1 从头header中获取令牌数据
        String token = request.getHeaders().getFirst(AUTHORIZE_TOKEN);

        if(StringUtils.isEmpty(token)){
            //4.2 从cookie中中获取令牌数据
            HttpCookie first = request.getCookies().getFirst(AUTHORIZE_TOKEN);
            if(first!=null){
                token=first.getValue();//就是令牌的数据
            }
            hasToken = false;
        }

        if(StringUtils.isEmpty(token)){
            //4.3 从请求参数中获取令牌数据
            token= request.getQueryParams().getFirst(AUTHORIZE_TOKEN);
            hasToken = false;
        }

        //如果没有令牌则拦截
        if(StringUtils.isEmpty(token)){
            //4.4. 如果没有数据 结束.  设置没有权限的状态码
            response.setStatusCode(HttpStatus.UNAUTHORIZED);  //响应状态码401
            return response.setComplete();   //响应空数据
        }else {
            //如果请求头中没有bearer
            if (!hasToken) {
                //判断是否有前缀bearer， 如果没有则添加前缀
                if (!token.startsWith("bearer   ") && !token.startsWith("Bearer ")) {
                    token = "bearer " + token;
                }
                //将令牌封装到头文件中
                request.mutate().header(AUTHORIZE_TOKEN,token);
            }
        }


        //5 解析令牌数据 ( 判断解析是否正确,正确 就放行 ,否则 结束)
        try {
            //原来没有使用密钥时候的方法
            //Claims claims = JwtUtil.parseJWT(token);

        } catch (Exception e) {
            e.printStackTrace();
            //解析失败
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
            return response.setComplete();
        }

        /* 提升到前面
        if (!hasToken){
            //将令牌封装到头文件中
            request.mutate().header(AUTHORIZE_TOKEN,token);
        }*/

        //有效放行
        return chain.filter(exchange);
    }

    @Override
    public int getOrder() {
        return 0;
    }
}
