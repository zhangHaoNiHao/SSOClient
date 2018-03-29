package sso.client;

public class User {
	public User(){}
	private int id;
	private String name;
	private String password;
	private String account;
	public int getId() {
		return id;
	}
	public void setId(int id) {
		this.id = id;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public String getPassword() {
		return password;
	}
	public void setPassword(String password) {
		this.password = password;
	}
	public String getAccount() {
		return account;
	}
	public void setAccount(String account) {
		this.account = account;
	}
	public User(int id, String name, String password, String account) {
		super();
		this.id = id;
		this.name = name;
		this.password = password;
		this.account = account;
	}
	@Override
	public String toString() {
		return "User [id=" + id + ", name=" + name + ", password=" + password + ", account=" + account + "]";
	}
	
}
