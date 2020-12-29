package com.yujl.modules.api.repository;

import com.yujl.modules.api.domain.TbRefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

public interface RefreshTokenDao extends JpaRepository<TbRefreshToken,Long>, JpaSpecificationExecutor<TbRefreshToken> {
    TbRefreshToken findOneByTokenKey(String tokenKey);
    int deleteAllByUserId(Long UserID);

    int deleteAllByTokenKey(String tokenKey);
}
