package com.yujl.repository;

import com.yujl.domain.TbSettings;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

public interface SettingsDao extends JpaRepository<TbSettings,String>, JpaSpecificationExecutor<TbSettings> {

    TbSettings findOneByKey(String key);
}
