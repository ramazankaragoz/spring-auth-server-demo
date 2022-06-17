package com.demo.authzdemo.service;

import lombok.Data;

import javax.persistence.*;

@Data
@Entity
@Table(name = "user_entity")
public class UserEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String username;
    private Boolean enabled=Boolean.TRUE;

}
