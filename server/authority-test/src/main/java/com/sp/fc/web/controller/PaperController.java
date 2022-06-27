package com.sp.fc.web.controller;

import com.sp.fc.web.service.Paper;
import com.sp.fc.web.service.PaperService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/paper")
public class PaperController {

    @Autowired
    private PaperService paperService;

    @PreAuthorize("isStudent()")
    @GetMapping("/mypapers")
    public List<Paper> myPapers(@AuthenticationPrincipal User user, @PathVariable Long paperId){
        return paperService.getMyPapers(user.getUsername());
    }

    @PreAuthorize("hasPermission(#paperId, 'paper', 'read')") // paperId는 PATH, paper는 paper, read는 권한
    @GetMapping("/get/{parentId}")
    public Paper getPaper(@AuthenticationPrincipal User user, @PathVariable Long paperId){
        return paperService.getPaper(paperId);
    }

}
