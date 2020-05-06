package com.algaworks.algafood.auth.core;

import com.algaworks.algafood.auth.domain.Grupo;
import com.algaworks.algafood.auth.domain.Permissao;
import com.algaworks.algafood.auth.domain.Usuario;
import com.algaworks.algafood.auth.domain.UsuarioRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collection;
import java.util.stream.Collectors;

@Service
public class JpaUserDetailsService implements UserDetailsService {

    final UsuarioRepository usuarioRepository;

    public JpaUserDetailsService(UsuarioRepository usuarioRepository) {
        this.usuarioRepository = usuarioRepository;
    }

    @Transactional(readOnly = true)
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Usuario usuario = usuarioRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("Usuário não encontrado com e-mail informado."));

        return new AuthUser(usuario, getAuthorities(usuario));
    }

    private Collection<GrantedAuthority> getAuthorities(Usuario usuario) {
        return usuario.getGrupos().stream()
                .flatMap((Grupo grupo) -> grupo.getPermissoes().stream())
                .map((Permissao permissao) -> new SimpleGrantedAuthority(permissao.getNome().toUpperCase()))
                .collect(Collectors.toSet());
    }
}
