package com.microservices.merchantOnboarding.merchantOnboarding.EntityModel;




import javax.persistence.*;

@Entity
@Table(name = "AuthTransaction")
public class AuthTransaction {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long transactionId;

    private String username;
    private String password;

	@Column(name="Status")
    private String status;
	@Column(name="Reason")
    private String reason;


    protected AuthTransaction() {
    }

	public AuthTransaction(Long transactionId,String username,String password,
						    String status,String reason) {
		super();
		this.transactionId = transactionId;
		this.username=username;
		this.password=password;
		this.status = status;
		this.reason=reason;
	}

	public Long getTransactionTd() {
		return transactionId;
	}

	public void setTransactionTd(Long transactionTd) {
		this.transactionId = transactionTd;
	}


	public String getStatus() {
		return status;
	}

	public void setStatus(String status) {
		this.status = status;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getReason() {
		return reason;
	}

	public void setReason(String reason) {
		this.reason = reason;
	}
}