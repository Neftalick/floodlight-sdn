package net.floodlightcontroller.autorization;


import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.types.EthType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.*;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

public class Autorization implements IOFMessageListener, IFloodlightModule {
    //Variables necesarias
    protected IFloodlightProviderService floodlightProvider;
    protected static Logger logger;



    @Override
    public String getName() {
        return Autorization.class.getSimpleName();
    }

    @Override
    public boolean isCallbackOrderingPrereq(OFType type, String name) {
        return false;
    }

    @Override
    public boolean isCallbackOrderingPostreq(OFType type, String name) {
        return (type.equals(OFType.PACKET_IN) && name.equals("forwarding"));
    }

    @Override
    public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
        //Debemos obtener la mac e ip de la petición
        switch (msg.getType()) {
            case PACKET_IN:
                boolean existeUsuario = false;
                Ethernet ethernet =
                        IFloodlightProviderService.bcStore.get(cntx,
                                IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
                if (!ethernet.isBroadcast() && ethernet.getEtherType() == EthType.IPv4) {
                    //Casteo a string de la mac
                    String sourceMac = ethernet.getSourceMACAddress().toString();
                    IPv4 iPv4 = (IPv4) ethernet.getPayload();
                    try {
                        Class.forName("com.mysql.cj.jdbc.Driver");
                    } catch (ClassNotFoundException e) {
                        logger.info("problema con el driver");
                        System.out.println("efectivamente problema con el dirver");
                        e.printStackTrace();
                    }
                    //Validamos que la Ip origen no provenga de un servicio
                    boolean isService = false;
                    List<String> listaServicios = new ArrayList<>();
                    //Obtenemos todos los servicios
                    try {
                        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/servicios?useSSL=false", "ubuntu", "ubuntu");
                        try (Statement stmt = conn.createStatement()) {
                            System.out.println(stmt.toString());
                            ResultSet resultSet = stmt.executeQuery("SELECT * FROM servicio");
                            while (resultSet.next()) {
                                listaServicios.add(resultSet.getString("IP"));
                            }
                            logger.info("Servicio (IPs)");
                            for (String element:listaServicios) {
                                logger.info(element);
                            }
                            isService = listaServicios.contains(iPv4.getSourceAddress().toString());
                        } catch (SQLException sqlException) {
                            logger.info("Error");
                            System.out.println("error de conexion con la db");
                        }
                    } catch (SQLException e) {
                        logger.info(e.getMessage());
                    }

                    //Verificamos que no sea un paquete del controlador
                    if (!iPv4.getSourceAddress().toString().equals("192.168.5.200") && !isService){
                        //Casteo a string del ip
                        boolean usuarioPerteneceServicio = false;
                        List<String> usuariosPertenecenServicio = new ArrayList<>();
                        String usuario = "";
                        String ipv4Source = iPv4.getSourceAddress().toString();
                        String ipv4Dest = iPv4.getDestinationAddress().toString();
                        logger.info("MAC, IP origen :");
                        logger.info(sourceMac);
                        logger.info(ipv4Source);
                        logger.info("IP destino: ");
                        logger.info(ipv4Dest);
                        //Obtenemos el usuario relacionado con el equipo que inicia la conexión
                        try {
                            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/usuarios_autenticados?useSSL=false", "ubuntu", "ubuntu");
                            try (PreparedStatement stmt = conn.prepareStatement("SELECT * FROM usuario_autenticado where Dispositivo_dispositivo_MAC = ? and IP = ?")) {
                                stmt.setString(1, sourceMac);
                                stmt.setString(2, ipv4Source);
                                //System.out.println("Busca del usuario");
                                //System.out.println(stmt.toString());
                                ResultSet resultSet = stmt.executeQuery();
                                while (resultSet.next()) {
                                    System.out.println("Usuario obtenido: "+String.valueOf(resultSet.getInt("idUsuario_Autenticado")));
                                    usuario = String.valueOf(resultSet.getInt("idUsuario_Autenticado"));
                                    existeUsuario = true;
                                }
                            } catch (SQLException sqlException) {
                                logger.info("Error");
                                System.out.println("error de conexion con la db");
                            }
                        } catch (SQLException e) {
                            logger.info(e.getMessage());
                        }

                        System.out.println("Estado- existe usuario "+ existeUsuario);
                        if (existeUsuario){
                            try {
                                Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/servicios?useSSL=false", "ubuntu", "ubuntu");
                                try (PreparedStatement stmt = conn.prepareStatement("SELECT p.usuario FROM servicio s inner join servicio_has_participantes sp on sp.Servicio_idServicio = s.idServicio inner join participantes p on sp.Participantes_idParticipantes = p.idParticipantes where s.IP = ? ")) {
                                    stmt.setString(1, ipv4Dest);
                                    System.out.println("Busca de los usuarios enlazados al servicio");
                                    System.out.println(stmt.toString());
                                    ResultSet resultSet = stmt.executeQuery();
                                    while (resultSet.next()) {
                                        System.out.println("Usuario obtenido perteneciente al servicio: " + String.valueOf(resultSet.getInt("usuario")));
                                        usuariosPertenecenServicio.add(String.valueOf(resultSet.getInt("usuario")));
                                    }
                                    usuarioPerteneceServicio = usuariosPertenecenServicio.contains(usuario);
                                } catch (SQLException sqlException) {
                                    logger.info("Error");
                                    System.out.println("error de conexion con la db");
                                }
                            } catch (SQLException e) {
                                logger.info(e.getMessage());
                            }
                        }else {
                            logger.info("Petición bloqueada");
                            return Command.STOP;
                        }
                        if (usuarioPerteneceServicio){
                            logger.info("Paquete autorizado");
                            return Command.CONTINUE;
                        }else {
                            logger.info("Petición bloqueada");
                            return Command.STOP;
                        }
                    }else {
                        logger.info("Se salto el modulo de autorización porque es un servicio");
                        return Command.CONTINUE;
                    }
                }
                break;
            default:
                break;
        }
        return Command.CONTINUE;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleServices() {
        return null;
    }

    @Override
    public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
        return null;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
        Collection<Class<? extends IFloodlightService >> l =
                new ArrayList<>();
        l.add(IFloodlightProviderService.class);
        return  l;
    }

    @Override
    public void init(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
        logger = LoggerFactory.getLogger(Autorization.class);
    }

    @Override
    public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
    }
}
