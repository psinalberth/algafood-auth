package com.algaworks.algafood.auth.core;

import com.algaworks.algafood.auth.domain.Usuario;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

@Getter
public class AuthUser extends User {

    private Long id;
    private String fullName;

    public AuthUser(Usuario usuario, Collection<GrantedAuthority> authorities) {
        super(usuario.getEmail(), usuario.getSenha(), authorities);
        this.fullName = usuario.getNome();
        this.id = usuario.getId();
    }
}