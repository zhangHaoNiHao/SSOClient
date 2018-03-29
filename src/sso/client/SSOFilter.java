package sso.client;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import util.CookieUtil;

public class SSOFilter implements Filter{

	//SSO Server登录页面URL
	private static final String SSO_LOGIN_URL = "/server/login",
			SSO_VALIDATE_URL="http://localhost:8080/server/validate";
	@Override
	public void destroy() {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		System.out.println("SSOClient 拦截器");
		HttpServletRequest req = (HttpServletRequest) request;
		HttpServletResponse resp = (HttpServletResponse) response;
		//从请求中提取token
		String token = CookieUtil.getCookie(req,"token");
		//本次请求的完整路径:例如访问localhost：8080/app1/index.jsp就是获取的该路径
		String origUrl = req.getRequestURL().toString();//路径中？之前
		String queryStr = req.getQueryString();//路径中？之后的
		System.out.println("原始路径之前 "+origUrl+" 路径之后 "+queryStr);
		if(queryStr != null)
		{
			origUrl +="?"+queryStr;//拼接
			System.out.println("获得原始路径"+origUrl);
		}
		//token不存在，跳转到SSOServer用户登录页面
		if(token == null)
		{
			System.out.println("token为空，去登录页面授权");
			resp.sendRedirect(SSO_LOGIN_URL+"?origUrl="+URLEncoder.encode(origUrl, "utf-8"));
		}else{//token若存在，到SSOServer中验证有效性
			System.out.println("token存在，转到validateServlet去验证是否有效");
			URL validateUrl = new URL(SSO_VALIDATE_URL+"?token="+token);
			HttpURLConnection conn = (HttpURLConnection) validateUrl.openConnection();
			conn.connect();
			InputStream is = conn.getInputStream();
			byte[] buffer = new byte[is.available()];
			is.read(buffer);
			String ret = new String(buffer);//如果token有效，返回一个序列化的数据，否则为空字符串
			
			if(ret.length() == 0){//返回空字符串，说明token无效
				System.out.println("token无效，返回登录页面,并传入origUrl"+origUrl);
				resp.sendRedirect(SSO_LOGIN_URL+"?origUrl="+URLEncoder.encode(origUrl,"utf-8"));
			}else{
				System.out.println("token有效，获得User继续访问");
				String[] tmp = ret.split(";");
				User user = new User();
				for(int i=0;i<tmp.length;++i)
				{
					String[] attrs = tmp[i].split("=");
					switch(attrs[0])
					{
					case "id":
						user.setId(Integer.parseInt(attrs[1]));
						break;
					case "name":
						user.setName(attrs[1]);
						break;
					case "account":
						user.setAccount(attrs[1]);
						break;
					}
				}
				request.setAttribute("user", user);
				chain.doFilter(request, response);
			}
		}
	}

	@Override
	public void init(FilterConfig arg0) throws ServletException {
		// TODO Auto-generated method stub
		
	}

}
