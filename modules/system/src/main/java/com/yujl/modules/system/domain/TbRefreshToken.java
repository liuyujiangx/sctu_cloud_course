package com.yujl.modules.system.domain;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;
import java.util.Date;

@Entity
@Table(name = "tb_refresh_token")
public class TbRefreshToken {

  @Id
  @Column(name = "id")
  private Long id;
  @Column(name = "refresh_token")
  private String refreshToken;
  @Column(name = "user_id")
  private Long userId;
  @Column(name = "token_key")
  private String tokenKey;
  @Column(name = "create_time")
  private Date createTime;
  @Column(name = "update_time")
  private Date updateTime;


  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }


  public String getRefreshToken() {
    return refreshToken;
  }

  public void setRefreshToken(String refreshToken) {
    this.refreshToken = refreshToken;
  }


  public Long getUserId() {
    return userId;
  }

  public void setUserId(Long userId) {
    this.userId = userId;
  }


  public String getTokenKey() {
    return tokenKey;
  }

  public void setTokenKey(String tokenKey) {
    this.tokenKey = tokenKey;
  }


  public Date getCreateTime() {
    return createTime;
  }

  public void setCreateTime(Date createTime) {
    this.createTime = createTime;
  }

  public Date getUpdateTime() {
    return updateTime;
  }

  public void setUpdateTime(Date updateTime) {
    this.updateTime = updateTime;
  }
}
