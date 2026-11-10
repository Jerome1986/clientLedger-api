import { Body, Controller, Post } from '@nestjs/common'
import { AdminService } from './admin.service'
import { LoginAdminDto } from './dto/login-admin.dto'

@Controller('admin')
export class AdminController {
  constructor(private readonly adminService: AdminService) { }

  // PC登录
  @Post('loginPc')
  loginPc(@Body() dto: LoginAdminDto) {
    return this.adminService.loginPc(dto)
  }
}
