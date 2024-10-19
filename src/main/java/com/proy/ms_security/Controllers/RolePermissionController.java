package com.proy.ms_security.Controllers;

import com.proy.ms_security.Models.Permission;
import com.proy.ms_security.Models.Role;
import com.proy.ms_security.Models.RolePermission;
import com.proy.ms_security.Repositories.PermissionRepository;
import com.proy.ms_security.Repositories.RolePermissionRepository;
import com.proy.ms_security.Repositories.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@CrossOrigin
@RestController
@RequestMapping("/role-permission")
public class RolePermissionController {

    @Autowired
    private RoleRepository theRoleRepository;
    @Autowired
    private PermissionRepository thePermissionRepository;
    @Autowired
    private RolePermissionRepository theRolePermissionRepository;

    @ResponseStatus(HttpStatus.CREATED)
    @PostMapping("role/{roleId}/permission/{permissionId}")
    public RolePermission create(@PathVariable String roleId, @PathVariable String permissionId){
        Role theRole = this.theRoleRepository.findById(roleId).orElse(null);
        Permission thePermission = this.thePermissionRepository.findById(permissionId).orElse(null);
        if(theRole != null && thePermission != null){
            RolePermission newRolePermission = new RolePermission();
            newRolePermission.setRole(theRole);
            newRolePermission.setPermission(thePermission);
            return this.theRolePermissionRepository.save(newRolePermission);
        }else {
            return null;
        }
    }

    @GetMapping("/{id}")
    public ResponseEntity<RolePermission> findById(@PathVariable String id) {
        Optional<RolePermission> rolePermission = theRolePermissionRepository.findById(id);
        return rolePermission.map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @ResponseStatus(HttpStatus.NO_CONTENT)
    @DeleteMapping("{id}")
    public void delete(@PathVariable String id) {
        RolePermission theRolePermission = this.theRolePermissionRepository
                .findById(id)
                .orElse(null);
        if (theRolePermission != null) {
            this.theRolePermissionRepository.delete(theRolePermission);
        }
    }

    @GetMapping("role/{roleId}")
    public List<RolePermission> findByRole(@PathVariable String roleId){
        return this.theRolePermissionRepository.getPermissionsByRole(roleId);
    }

    @GetMapping
    public List<RolePermission> findAll() {
        return this.theRolePermissionRepository.findAll();
    }
}