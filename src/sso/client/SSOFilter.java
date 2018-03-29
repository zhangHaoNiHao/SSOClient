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

	//SSO Server��¼ҳ��URL
	private static final String SSO_LOGIN_URL = "/server/login",
			SSO_VALIDATE_URL="http://localhost:8080/server/validate";
	@Override
	public void destroy() {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		System.out.println("SSOClient ������");
		HttpServletRequest req = (HttpServletRequest) request;
		HttpServletResponse resp = (HttpServletResponse) response;
		//����������ȡtoken
		String token = CookieUtil.getCookie(req,"token");
		//�������������·��:�������localhost��8080/app1/index.jsp���ǻ�ȡ�ĸ�·��
		String origUrl = req.getRequestURL().toString();//·���У�֮ǰ
		String queryStr = req.getQueryString();//·���У�֮���
		System.out.println("ԭʼ·��֮ǰ "+origUrl+" ·��֮�� "+queryStr);
		if(queryStr != null)
		{
			origUrl +="?"+queryStr;//ƴ��
			System.out.println("���ԭʼ·��"+origUrl);
		}
		//token�����ڣ���ת��SSOServer�û���¼ҳ��
		if(token == null)
		{
			System.out.println("tokenΪ�գ�ȥ��¼ҳ����Ȩ");
			resp.sendRedirect(SSO_LOGIN_URL+"?origUrl="+URLEncoder.encode(origUrl, "utf-8"));
		}else{//token�����ڣ���SSOServer����֤��Ч��
			System.out.println("token���ڣ�ת��validateServletȥ��֤�Ƿ���Ч");
			URL validateUrl = new URL(SSO_VALIDATE_URL+"?token="+token);
			HttpURLConnection conn = (HttpURLConnection) validateUrl.openConnection();
			conn.connect();
			InputStream is = conn.getInputStream();
			byte[] buffer = new byte[is.available()];
			is.read(buffer);
			String ret = new String(buffer);//���token��Ч������һ�����л������ݣ�����Ϊ���ַ���
			
			if(ret.length() == 0){//���ؿ��ַ�����˵��token��Ч
				System.out.println("token��Ч�����ص�¼ҳ��,������origUrl"+origUrl);
				resp.sendRedirect(SSO_LOGIN_URL+"?origUrl="+URLEncoder.encode(origUrl,"utf-8"));
			}else{
				System.out.println("token��Ч�����User��������");
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
