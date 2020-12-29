package com.yujl.modules.api.repository;

import com.yujl.modules.api.domain.TbSettings;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

public interface SettingsDao extends JpaRepository<TbSettings,String>, JpaSpecificationExecutor<TbSettings> {

    TbSettings findOneByKey(String key);
}
