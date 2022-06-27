package com.sp.fc.web.config;

import org.springframework.stereotype.Component;
import sun.awt.SunHints;

@Component(value = "nameCheck")
public class NameCheck {

    public boolean check(String name){
        return name.equals("shbae");
    }

}
