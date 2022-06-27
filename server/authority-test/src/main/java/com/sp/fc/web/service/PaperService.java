package com.sp.fc.web.service;

import org.springframework.beans.factory.InitializingBean;

import java.util.HashMap;
import java.util.List;
import java.util.stream.Collectors;

public class PaperService implements InitializingBean {

    private HashMap<Long, Paper> paperDB = new HashMap<>();

    @Override
    public void afterPropertiesSet() throws Exception {

    }

    public void setPaper(Paper paper){
        paperDB.put(paper.getPaperId(), paper);
    }

    public List<Paper> getMyPapers(String userName){
        return paperDB.values().stream().filter(
                paper -> paper.getStudentIds().contains(userName)
        ).collect(Collectors.toList());
    }

    public Paper getPaper(Long paperId){
        return paperDB.get(paperId);
    }
}
