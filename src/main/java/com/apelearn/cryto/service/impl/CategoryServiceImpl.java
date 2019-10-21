package com.apelearn.cryto.service.impl;

import com.apelearn.cryto.mapper.CategoryMapper;
import com.apelearn.cryto.model.Category;
import com.apelearn.cryto.service.CategoryService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * Created by mac on 2019/10/20.
 */
@Service
public class CategoryServiceImpl implements CategoryService{

    @Autowired
    private CategoryMapper categoryMapper;

    @Override
    public int save(Category category) {
        return categoryMapper.insert(category);
    }
}
