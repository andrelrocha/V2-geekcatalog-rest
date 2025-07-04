package com.geekcatalog.api.domain.utils.views;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.ModelAndView;

@Component
public class SignInView {

    public ModelAndView signInForm() {
        ModelAndView modelAndView = new ModelAndView("sign-in");

        return modelAndView;
    }

}
